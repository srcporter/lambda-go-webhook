package main

import (
        //"fmt"
        "log"
        "net/http"
        "context"
        "time"
        "encoding/json"
        "github.com/aws/aws-lambda-go/lambda"
        "github.com/aws/aws-lambda-go/events"
)

type SRAlert struct {
	Alert struct {
		ID     string `json:"id"`
		Policy struct {
			ID          string   `json:"id"`
			Name        string   `json:"name"`
			Description string   `json:"description"`
			Rationale   string   `json:"rationale"`
			Remediation string   `json:"remediation"`
			Disabled    bool     `json:"disabled"`
			Categories  []string `json:"categories"`
			Fields      struct {
				ImageName struct {
					Registry string `json:"registry"`
					Remote   string `json:"remote"`
					Tag      string `json:"tag"`
				} `json:"imageName"`
				ImageAgeDays string `json:"imageAgeDays"`
				LineRule     struct {
					Instruction string `json:"instruction"`
					Value       string `json:"value"`
				} `json:"lineRule"`
				Cvss struct {
					Op    string `json:"op"`
					Value int    `json:"value"`
				} `json:"cvss"`
				Cve       string `json:"cve"`
				Component struct {
					Name    string `json:"name"`
					Version string `json:"version"`
				} `json:"component"`
				ScanAgeDays  string `json:"scanAgeDays"`
				NoScanExists bool   `json:"noScanExists"`
				Env          struct {
					Key          string `json:"key"`
					Value        string `json:"value"`
					EnvVarSource string `json:"envVarSource"`
				} `json:"env"`
				Command      string `json:"command"`
				Args         string `json:"args"`
				Directory    string `json:"directory"`
				User         string `json:"user"`
				VolumePolicy struct {
					Name        string `json:"name"`
					Source      string `json:"source"`
					Destination string `json:"destination"`
					ReadOnly    bool   `json:"readOnly"`
					Type        string `json:"type"`
				} `json:"volumePolicy"`
				PortPolicy struct {
					Port     int    `json:"port"`
					Protocol string `json:"protocol"`
				} `json:"portPolicy"`
				RequiredLabel struct {
					Key          string `json:"key"`
					Value        string `json:"value"`
					EnvVarSource string `json:"envVarSource"`
				} `json:"requiredLabel"`
				RequiredAnnotation struct {
					Key          string `json:"key"`
					Value        string `json:"value"`
					EnvVarSource string `json:"envVarSource"`
				} `json:"requiredAnnotation"`
				DisallowedAnnotation struct {
					Key          string `json:"key"`
					Value        string `json:"value"`
					EnvVarSource string `json:"envVarSource"`
				} `json:"disallowedAnnotation"`
				Privileged              bool     `json:"privileged"`
				DropCapabilities        []string `json:"dropCapabilities"`
				AddCapabilities         []string `json:"addCapabilities"`
				ContainerResourcePolicy struct {
					CPUResourceRequest struct {
						Op    string `json:"op"`
						Value int    `json:"value"`
					} `json:"cpuResourceRequest"`
					CPUResourceLimit struct {
						Op    string `json:"op"`
						Value int    `json:"value"`
					} `json:"cpuResourceLimit"`
					MemoryResourceRequest struct {
						Op    string `json:"op"`
						Value int    `json:"value"`
					} `json:"memoryResourceRequest"`
					MemoryResourceLimit struct {
						Op    string `json:"op"`
						Value int    `json:"value"`
					} `json:"memoryResourceLimit"`
				} `json:"containerResourcePolicy"`
				ProcessPolicy struct {
					Name     string `json:"name"`
					Args     string `json:"args"`
					Ancestor string `json:"ancestor"`
					UID      string `json:"uid"`
				} `json:"processPolicy"`
				ReadOnlyRootFs     bool   `json:"readOnlyRootFs"`
				FixedBy            string `json:"fixedBy"`
				PortExposurePolicy struct {
					ExposureLevels []string `json:"exposureLevels"`
				} `json:"portExposurePolicy"`
				PermissionPolicy struct {
					PermissionLevel string `json:"permissionLevel"`
				} `json:"permissionPolicy"`
				HostMountPolicy struct {
					ReadOnly bool `json:"readOnly"`
				} `json:"hostMountPolicy"`
				WhitelistEnabled   bool `json:"whitelistEnabled"`
				RequiredImageLabel struct {
					Key          string `json:"key"`
					Value        string `json:"value"`
					EnvVarSource string `json:"envVarSource"`
				} `json:"requiredImageLabel"`
				DisallowedImageLabel struct {
					Key          string `json:"key"`
					Value        string `json:"value"`
					EnvVarSource string `json:"envVarSource"`
				} `json:"disallowedImageLabel"`
			} `json:"fields"`
			LifecycleStages []string `json:"lifecycleStages"`
			Whitelists      []struct {
				Name       string `json:"name"`
				Deployment struct {
					Name  string `json:"name"`
					Scope struct {
						Cluster   string `json:"cluster"`
						Namespace string `json:"namespace"`
						Label     struct {
							Key   string `json:"key"`
							Value string `json:"value"`
						} `json:"label"`
					} `json:"scope"`
				} `json:"deployment"`
				Image struct {
					Name string `json:"name"`
				} `json:"image"`
				Expiration time.Time `json:"expiration"`
			} `json:"whitelists"`
			Scope []struct {
				Cluster   string `json:"cluster"`
				Namespace string `json:"namespace"`
				Label     struct {
					Key   string `json:"key"`
					Value string `json:"value"`
				} `json:"label"`
			} `json:"scope"`
			Severity           string    `json:"severity"`
			EnforcementActions []string  `json:"enforcementActions"`
			Notifiers          []string  `json:"notifiers"`
			LastUpdated        time.Time `json:"lastUpdated"`
			SORTName           string    `json:"SORTName"`
			SORTLifecycleStage string    `json:"SORTLifecycleStage"`
			SORTEnforcement    bool      `json:"SORTEnforcement"`
			PolicyVersion      string    `json:"policyVersion"`
			PolicySections     []struct {
				SectionName  string `json:"sectionName"`
				PolicyGroups []struct {
					FieldName       string `json:"fieldName"`
					BooleanOperator string `json:"booleanOperator"`
					Negate          bool   `json:"negate"`
					Values          []struct {
						Value string `json:"value"`
					} `json:"values"`
				} `json:"policyGroups"`
			} `json:"policySections"`
		} `json:"policy"`
		LifecycleStage string `json:"lifecycleStage"`
		Deployment     struct {
			ID          string `json:"id"`
			Name        string `json:"name"`
			Type        string `json:"type"`
			Namespace   string `json:"namespace"`
			NamespaceID string `json:"namespaceId"`
			Labels      struct {
				Property1 string `json:"property1"`
				Property2 string `json:"property2"`
			} `json:"labels"`
			ClusterID   string `json:"clusterId"`
			ClusterName string `json:"clusterName"`
			Containers  []struct {
				Image struct {
					ID   string `json:"id"`
					Name struct {
						Registry string `json:"registry"`
						Remote   string `json:"remote"`
						Tag      string `json:"tag"`
						FullName string `json:"fullName"`
					} `json:"name"`
					NotPullable bool `json:"notPullable"`
				} `json:"image"`
				Name string `json:"name"`
			} `json:"containers"`
			Annotations struct {
				Property1 string `json:"property1"`
				Property2 string `json:"property2"`
			} `json:"annotations"`
			Inactive bool `json:"inactive"`
		} `json:"deployment"`
		Violations []struct {
			Message             string `json:"message"`
			DEPRECATEDProcesses []struct {
				ID            string `json:"id"`
				DeploymentID  string `json:"deploymentId"`
				ContainerName string `json:"containerName"`
				PodID         string `json:"podId"`
				PodUID        string `json:"podUid"`
				Signal        struct {
					ID           string    `json:"id"`
					ContainerID  string    `json:"containerId"`
					Time         time.Time `json:"time"`
					Name         string    `json:"name"`
					Args         string    `json:"args"`
					ExecFilePath string    `json:"execFilePath"`
					Pid          int       `json:"pid"`
					UID          int       `json:"uid"`
					Gid          int       `json:"gid"`
					Lineage      []string  `json:"lineage"`
					Scraped      bool      `json:"scraped"`
					LineageInfo  []struct {
						ParentUID          int    `json:"parentUid"`
						ParentExecFilePath string `json:"parentExecFilePath"`
					} `json:"lineageInfo"`
				} `json:"signal"`
				ClusterID          string    `json:"clusterId"`
				Namespace          string    `json:"namespace"`
				ContainerStartTime time.Time `json:"containerStartTime"`
			} `json:"DEPRECATEDProcesses"`
		} `json:"violations"`
		ProcessViolation struct {
			Message   string `json:"message"`
			Processes []struct {
				ID            string `json:"id"`
				DeploymentID  string `json:"deploymentId"`
				ContainerName string `json:"containerName"`
				PodID         string `json:"podId"`
				PodUID        string `json:"podUid"`
				Signal        struct {
					ID           string    `json:"id"`
					ContainerID  string    `json:"containerId"`
					Time         time.Time `json:"time"`
					Name         string    `json:"name"`
					Args         string    `json:"args"`
					ExecFilePath string    `json:"execFilePath"`
					Pid          int       `json:"pid"`
					UID          int       `json:"uid"`
					Gid          int       `json:"gid"`
					Lineage      []string  `json:"lineage"`
					Scraped      bool      `json:"scraped"`
					LineageInfo  []struct {
						ParentUID          int    `json:"parentUid"`
						ParentExecFilePath string `json:"parentExecFilePath"`
					} `json:"lineageInfo"`
				} `json:"signal"`
				ClusterID          string    `json:"clusterId"`
				Namespace          string    `json:"namespace"`
				ContainerStartTime time.Time `json:"containerStartTime"`
			} `json:"processes"`
		} `json:"processViolation"`
		Enforcement struct {
			Action  string `json:"action"`
			Message string `json:"message"`
		} `json:"enforcement"`
		Time          time.Time `json:"time"`
		FirstOccurred time.Time `json:"firstOccurred"`
		State         string    `json:"state"`
		SnoozeTill    time.Time `json:"snoozeTill"`
		Tags          []string  `json:"tags"`
	} `json:"alert"`
}

type AlertBody struct {
    AlertID string
    Name string
}

func apiResponse(status int, body interface{}) (*events.APIGatewayProxyResponse, error) {
      resp := events.APIGatewayProxyResponse{Headers: map[string]string{"Content-Type": "application/json"}}
      resp.StatusCode = status

      stringBody, _ := json.Marshal(body)
      resp.Body = string(stringBody)
      return &resp, nil
}

func HandleRequest(ctx context.Context, request events.APIGatewayProxyRequest) (*events.APIGatewayProxyResponse, error) {
        // the json from StackRox Central is the request Body
        log.Printf("Body size = %d.\n", len(request.Body))

        if request.HTTPMethod != "POST" {
            return UnhandledMethod()
        }

        // parse the alert JSON into the SRAlert struct
        var srevent SRAlert
        if err := json.Unmarshal([]byte(request.Body), &srevent); err != nil {
            log.Printf("could not unmarshal data into alert struct")
            return apiResponse (http.StatusOK, "Invalid alert data")
        }
        // if you want to extract or transform any alert data, do it here

        // create a cloudwatch log for the alert
        logjson, err := json.Marshal(srevent)
        if err != nil {
            log.Printf("Could not marshal json data into string for this alert")
            return apiResponse (http.StatusOK, "Invalid alert data")
        }
        log.Printf("%s", logjson)

        // ack with the ID and policy name
        alertbody := AlertBody{AlertID: srevent.Alert.ID, Name: srevent.Alert.Policy.Name}
        return apiResponse(http.StatusOK, alertbody)


        // as an alternative to the above, you can just log the alert request body:
        //log.Printf("%s", request.Body)
        //return apiResponse(http.StatusOK, "acknowledged")
}

func UnhandledMethod() (*events.APIGatewayProxyResponse, error) {
      return apiResponse(http.StatusMethodNotAllowed, "NotAllowed")
}

func main() {
        lambda.Start(HandleRequest)
}
