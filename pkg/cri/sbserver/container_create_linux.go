/*
   Copyright The containerd Authors.

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at

       http://www.apache.org/licenses/LICENSE-2.0

   Unless required by applicable law or agreed to in writing, software
   distributed under the License is distributed on an "AS IS" BASIS,
   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
   See the License for the specific language governing permissions and
   limitations under the License.
*/

package sbserver

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"

	imagespec "github.com/opencontainers/image-spec/specs-go/v1"
	runtime "k8s.io/cri-api/pkg/apis/runtime/v1"

	"github.com/containerd/containerd/contrib/apparmor"
	"github.com/containerd/containerd/contrib/seccomp"
	"github.com/containerd/containerd/oci"
	"github.com/containerd/containerd/snapshots"

	customopts "github.com/containerd/containerd/pkg/cri/opts"
)

const (
	// profileNamePrefix is the prefix for loading profiles on a localhost. Eg. AppArmor localhost/profileName.
	profileNamePrefix = "localhost/" // TODO (mikebrow): get localhost/ & runtime/default from CRI kubernetes/kubernetes#51747
	// runtimeDefault indicates that we should use or create a runtime default profile.
	runtimeDefault = "runtime/default"
	// dockerDefault indicates that we should use or create a docker default profile.
	dockerDefault = "docker/default"
	// appArmorDefaultProfileName is name to use when creating a default apparmor profile.
	appArmorDefaultProfileName = "cri-containerd.apparmor.d"
	// unconfinedProfile is a string indicating one should run a pod/containerd without a security profile
	unconfinedProfile = "unconfined"
	// seccompDefaultProfile is the default seccomp profile.
	seccompDefaultProfile = dockerDefault
)

func (c *criService) containerSpecOpts(config *runtime.ContainerConfig, imageConfig *imagespec.ImageConfig) ([]oci.SpecOpts, error) {
	var (
		specOpts []oci.SpecOpts
		err      error
	)
	securityContext := config.GetLinux().GetSecurityContext()
	userstr := "0" // runtime default
	if securityContext.GetRunAsUsername() != "" {
		userstr = securityContext.GetRunAsUsername()
	} else if securityContext.GetRunAsUser() != nil {
		userstr = strconv.FormatInt(securityContext.GetRunAsUser().GetValue(), 10)
	} else if imageConfig.User != "" {
		userstr, _, _ = strings.Cut(imageConfig.User, ":")
	}
	specOpts = append(specOpts, customopts.WithAdditionalGIDs(userstr),
		customopts.WithSupplementalGroups(securityContext.GetSupplementalGroups()))

	asp := securityContext.GetApparmor()
	if asp == nil {
		asp, err = generateApparmorSecurityProfile(securityContext.GetApparmorProfile()) //nolint:staticcheck // Deprecated but we don't want to remove yet
		if err != nil {
			return nil, fmt.Errorf("failed to generate apparmor spec opts: %w", err)
		}
	}
	apparmorSpecOpts, err := generateApparmorSpecOpts(
		asp,
		securityContext.GetPrivileged(),
		c.apparmorEnabled())
	if err != nil {
		return nil, fmt.Errorf("failed to generate apparmor spec opts: %w", err)
	}
	if apparmorSpecOpts != nil {
		specOpts = append(specOpts, apparmorSpecOpts)
	}

	ssp := securityContext.GetSeccomp()
	if ssp == nil {
		ssp, err = generateSeccompSecurityProfile(
			securityContext.GetSeccompProfilePath(), //nolint:staticcheck // Deprecated but we don't want to remove yet
			c.config.UnsetSeccompProfile)
		if err != nil {
			return nil, fmt.Errorf("failed to generate seccomp spec opts: %w", err)
		}
	}
	seccompSpecOpts, err := c.generateSeccompSpecOpts(
		ssp,
		securityContext.GetPrivileged(),
		c.seccompEnabled())
	if err != nil {
		return nil, fmt.Errorf("failed to generate seccomp spec opts: %w", err)
	}
	if seccompSpecOpts != nil {
		specOpts = append(specOpts, seccompSpecOpts)
	}
	if c.config.EnableCDI {
		specOpts = append(specOpts, customopts.WithCDI(config.Annotations, config.CDIDevices))
	}
	return specOpts, nil
}

func generateSeccompSecurityProfile(profilePath string, unsetProfilePath string) (*runtime.SecurityProfile, error) {
	if profilePath != "" {
		return generateSecurityProfile(profilePath)
	}
	if unsetProfilePath != "" {
		return generateSecurityProfile(unsetProfilePath)
	}
	return nil, nil
}
func generateApparmorSecurityProfile(profilePath string) (*runtime.SecurityProfile, error) {
	if profilePath != "" {
		return generateSecurityProfile(profilePath)
	}
	return nil, nil
}

func generateSecurityProfile(profilePath string) (*runtime.SecurityProfile, error) {
	switch profilePath {
	case runtimeDefault, dockerDefault, "":
		return &runtime.SecurityProfile{
			ProfileType: runtime.SecurityProfile_RuntimeDefault,
		}, nil
	case unconfinedProfile:
		return &runtime.SecurityProfile{
			ProfileType: runtime.SecurityProfile_Unconfined,
		}, nil
	default:
		// Require and Trim default profile name prefix
		if !strings.HasPrefix(profilePath, profileNamePrefix) {
			return nil, fmt.Errorf("invalid profile %q", profilePath)
		}
		return &runtime.SecurityProfile{
			ProfileType:  runtime.SecurityProfile_Localhost,
			LocalhostRef: strings.TrimPrefix(profilePath, profileNamePrefix),
		}, nil
	}
}

// generateSeccompSpecOpts generates containerd SpecOpts for seccomp.
func (c *criService) generateSeccompSpecOpts(sp *runtime.SecurityProfile, privileged, seccompEnabled bool) (oci.SpecOpts, error) {
	if privileged {
		// Do not set seccomp profile when container is privileged
		return nil, nil
	}
	if !seccompEnabled {
		if sp != nil {
			if sp.ProfileType != runtime.SecurityProfile_Unconfined {
				return nil, errors.New("seccomp is not supported")
			}
		}
		return nil, nil
	}

	if sp == nil {
		return nil, nil
	}

	if sp.ProfileType != runtime.SecurityProfile_Localhost && sp.LocalhostRef != "" {
		return nil, errors.New("seccomp config invalid LocalhostRef must only be set if ProfileType is Localhost")
	}
	switch sp.ProfileType {
	case runtime.SecurityProfile_Unconfined:
		// Do not set seccomp profile.
		return nil, nil
	case runtime.SecurityProfile_RuntimeDefault:
		return seccomp.WithDefaultProfile(), nil
	case runtime.SecurityProfile_Localhost:
		// trimming the localhost/ prefix just in case even though it should not
		// be necessary with the new SecurityProfile struct
		return seccomp.WithProfile(strings.TrimPrefix(sp.LocalhostRef, profileNamePrefix)), nil
	default:
		return nil, errors.New("seccomp unknown ProfileType")
	}
}

// generateApparmorSpecOpts generates containerd SpecOpts for apparmor.
func generateApparmorSpecOpts(sp *runtime.SecurityProfile, privileged, apparmorEnabled bool) (oci.SpecOpts, error) {
	if !apparmorEnabled {
		// Should fail loudly if user try to specify apparmor profile
		// but we don't support it.
		if sp != nil {
			if sp.ProfileType != runtime.SecurityProfile_Unconfined {
				return nil, errors.New("apparmor is not supported")
			}
		}
		return nil, nil
	}

	if sp == nil {
		// Based on kubernetes#51746, default apparmor profile should be applied
		// for when apparmor is not specified.
		sp, _ = generateSecurityProfile("")
	}

	if sp.ProfileType != runtime.SecurityProfile_Localhost && sp.LocalhostRef != "" {
		return nil, errors.New("apparmor config invalid LocalhostRef must only be set if ProfileType is Localhost")
	}

	switch sp.ProfileType {
	case runtime.SecurityProfile_Unconfined:
		// Do not set apparmor profile.
		return nil, nil
	case runtime.SecurityProfile_RuntimeDefault:
		if privileged {
			// Do not set apparmor profile when container is privileged
			return nil, nil
		}
		// TODO (mikebrow): delete created apparmor default profile
		return apparmor.WithDefaultProfile(appArmorDefaultProfileName), nil
	case runtime.SecurityProfile_Localhost:
		// trimming the localhost/ prefix just in case even through it should not
		// be necessary with the new SecurityProfile struct
		appArmorProfile := strings.TrimPrefix(sp.LocalhostRef, profileNamePrefix)
		if profileExists, err := appArmorProfileExists(appArmorProfile); !profileExists {
			if err != nil {
				return nil, fmt.Errorf("failed to generate apparmor spec opts: %w", err)
			}
			return nil, fmt.Errorf("apparmor profile not found %s", appArmorProfile)
		}
		return apparmor.WithProfile(appArmorProfile), nil
	default:
		return nil, errors.New("apparmor unknown ProfileType")
	}
}

// appArmorProfileExists scans apparmor/profiles for the requested profile
func appArmorProfileExists(profile string) (bool, error) {
	if profile == "" {
		return false, errors.New("nil apparmor profile is not supported")
	}
	profiles, err := os.Open("/sys/kernel/security/apparmor/profiles")
	if err != nil {
		return false, err
	}
	defer profiles.Close()

	rbuff := bufio.NewReader(profiles)
	for {
		line, err := rbuff.ReadString('\n')
		switch err {
		case nil:
			if strings.HasPrefix(line, profile+" (") {
				return true, nil
			}
		case io.EOF:
			return false, nil
		default:
			return false, err
		}
	}
}

// OverlayRWLayerSpec represents the configuration for overlay read-write layer storage
type OverlayRWLayerSpec struct {
	Name       string `json:"name"`       // Container name
	VolumeName string `json:"volumeName"` // Volume name from Pod spec
	Path       string `json:"path"`       // Path within the volume
}

// parseOverlayRWLayerSpecs parses the overlay-rw-layer-spec annotation
// Format: JSON array of OverlayRWLayerSpec objects
func parseOverlayRWLayerSpecs(specJSON string) ([]OverlayRWLayerSpec, error) {
	if specJSON == "" {
		return nil, nil
	}

	var specs []OverlayRWLayerSpec
	if err := json.Unmarshal([]byte(specJSON), &specs); err != nil {
		return nil, fmt.Errorf("failed to parse overlay-rw-layer-spec: %w", err)
	}

	return specs, nil
}

// findEbsPathForContainer finds the ebsPath for a specific container based on overlay-rw-layer-spec
func findEbsPathForContainer(containerName string, sandboxAnnotations map[string]string, mounts []*runtime.Mount) (string, error) {
	// Check for overlay-rw-layer-spec annotation (similar to VCI format)
	overlaySpecKey := "vci.volcengine.com/overlay-rw-layer-spec"
	if sandboxAnnotations == nil {
		return "", nil
	}

	specJSON, ok := sandboxAnnotations[overlaySpecKey]
	if !ok || specJSON == "" {
		return "", nil
	}

	specs, err := parseOverlayRWLayerSpecs(specJSON)
	if err != nil {
		return "", err
	}

	// Find the spec for this container
	for _, spec := range specs {
		if spec.Name == containerName {
			// Find the CSI volume mount path for the specified volumeName
			if spec.VolumeName == "" {
				continue
			}

			// Find CSI volume mount path by volume name
			csiMountPath := findCSIVolumeMountPathByVolumeName(spec.VolumeName, mounts)
			if csiMountPath == "" {
				// Try alternative matching - look for any CSI mount that might match
				csiMountPath = findCSIVolumeMountPath(spec.VolumeName, mounts)
			}

			if csiMountPath == "" {
				return "", fmt.Errorf("failed to find CSI volume mount path for volume %q", spec.VolumeName)
			}

			// Combine CSI mount path with the specified path
			ebsPath := csiMountPath
			if spec.Path != "" {
				ebsPath = strings.TrimSuffix(csiMountPath, "/") + "/" + strings.TrimPrefix(spec.Path, "/")
			}

			return ebsPath, nil
		}
	}

	return "", nil
}

// findCSIVolumeMountPathByVolumeName finds CSI volume mount path by volume name
// It looks through all mounts to find CSI volumes and tries to match by volume name
func findCSIVolumeMountPathByVolumeName(volumeName string, allMounts []*runtime.Mount) string {
	if volumeName == "" || len(allMounts) == 0 {
		return ""
	}

	// First, try to find by volume name in path (for volumes mounted by name)
	for _, mount := range allMounts {
		if mount == nil || mount.HostPath == "" {
			continue
		}

		// Check for CSI volume mounts
		if strings.Contains(mount.HostPath, "kubernetes.io~csi") {
			// Try to match volumeName - could be in the volume ID or path
			if strings.Contains(mount.HostPath, volumeName) {
				return mount.HostPath
			}
		}
	}

	// If not found by name, return empty and let caller handle
	return ""
}

// findCSIVolumeMountPath finds the mount path for a CSI volume by volume name
// from the container mounts. CSI volumes typically have paths like:
// /var/lib/kubelet/pods/{podUID}/volumes/kubernetes.io~csi/{volumeID}/mount
func findCSIVolumeMountPath(volumeName string, mounts []*runtime.Mount) string {
	if volumeName == "" || len(mounts) == 0 {
		return ""
	}

	// Look for CSI volume mount - CSI volumes are typically mounted with specific patterns
	// We check if the volume name appears in the mount path or if there's a matching pattern
	for _, mount := range mounts {
		if mount == nil || mount.HostPath == "" {
			continue
		}

		// Check if this is a CSI volume mount (contains kubernetes.io~csi in path)
		if strings.Contains(mount.HostPath, "kubernetes.io~csi") {
			// If volumeName is specified, we can match by:
			// 1. Direct path match if volumeName is already a full path
			if strings.Contains(mount.HostPath, volumeName) {
				return mount.HostPath
			}

			// 2. Extract volume ID from path and match
			// Path format: .../volumes/kubernetes.io~csi/{volumeID}/mount
			parts := strings.Split(mount.HostPath, "/")
			for i, part := range parts {
				if part == "kubernetes.io~csi" && i+1 < len(parts) {
					volumeID := parts[i+1]
					// Match if volumeName is part of volumeID or vice versa
					if strings.Contains(volumeID, volumeName) || strings.Contains(volumeName, volumeID) {
						return mount.HostPath
					}
				}
			}
		}
	}

	return ""
}

// snapshotterOpts returns any Linux specific snapshotter options for the rootfs snapshot
// containerName and sandboxAnnotations are needed for overlay-rw-layer-spec support
func snapshotterOpts(snapshotterName string, config *runtime.ContainerConfig, containerName string, sandboxAnnotations map[string]string, allMounts []*runtime.Mount) []snapshots.Opt {
	opts := []snapshots.Opt{}

	var ebsPath string

	// Priority 1: Check for overlay-rw-layer-spec annotation (VCI-style)
	// Format: vci.volcengine.com/overlay-rw-layer-spec with container-specific config
	if containerName != "" && sandboxAnnotations != nil {
		var err error
		ebsPath, err = findEbsPathForContainer(containerName, sandboxAnnotations, allMounts)
		if err != nil {
			// Log error but continue to try other methods
			_ = err
		}
	}

	// Priority 2: Check for direct ebsPath annotation
	if ebsPath == "" && config.Annotations != nil {
		ebsPathAnnotationKey := "io.containerd.snapshotter.v1.overlay/ebspath"
		if path, ok := config.Annotations[ebsPathAnnotationKey]; ok && path != "" {
			ebsPath = path
		}
	}

	// Priority 3: Check for CSI volume name annotation
	if ebsPath == "" && config.Annotations != nil {
		csiVolumeNameKey := "io.containerd.snapshotter.v1.overlay/ebs-volume-name"
		if volumeName, ok := config.Annotations[csiVolumeNameKey]; ok && volumeName != "" {
			if mounts := config.GetMounts(); len(mounts) > 0 {
				ebsPath = findCSIVolumeMountPath(volumeName, mounts)
			}
		}
	}

	if ebsPath != "" {
		// Add ebsPath to snapshot labels for overlay snapshotter
		labels := map[string]string{
			"containerd.io/snapshot/overlay.ebspath": ebsPath,
		}
		opts = append(opts, snapshots.WithLabels(labels))
	}

	return opts
}
