graph TB
  container_tool[ContainerTool]
  image[Image]
  utils[Utils]
  decorators[Decorators]
  flatten[Flatten]
  predicates[Predicates]
  abstract_finding[AbstractFinding]
  report_parser[ReportParser]
  hardening_manifest[HardeningManifest]
  vat_api[VatAPI]
  harbor_robot[HarborRobot]
  harbor_robot_permissions[HarborRobotPermissions]
  skopeo[Skopeo]
  package[Package]
  element_tree[ElementTree]
  oscap[Oscap]
  abstract_artifact[AbstractArtifact]
  anchore[Anchore]
  exceptions[Exceptions]
  s3_artifact[S3Artifact]
  http_artifact[HttpArtifact]
  container_artifact[ContainerArtifact]
  github_artifact[GithubArtifact]
  cosign[Cosign]
  
  // ... continue for all modules and classes
  
  container_tool --> image
  container_tool --> utils
  container_tool --> decorators
  
  image --> utils
  image --> decorators
  
  // ... continue for all relationships
  
  subgraph test_mocks
    mock_image[MockImage]
    mock_output[MockOutput]
    mock_path[MockPath]
    mock_popen[MockPopen]
    // ... continue for all mock classes
  end
  
  // ... continue
  
  class container_tool, image, utils, decorators {
    fill:#f9f,stroke:#333,stroke-width:4px
  }
