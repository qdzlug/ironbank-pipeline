```mermaid
graph TD
    container_tools[container_tools] --> ContainerTool
    container_tools --> Skopeo
    container_tools --> Cosign
    container_tools --> Buildah
    
    image[image] --> Image
    image --> ImageFile
    
    utils[utils] --> logger
    utils --> Package
    
    utils_decorators[utils.decorators] --> subprocess_error_handler
    utils_decorators --> key_index_error_handler
    utils_decorators --> request_retry
    utils_decorators --> vat_request_error_handler
    
    utils_exceptions[utils.exceptions] --> GenericSubprocessError
    utils_exceptions --> InvalidURLList
    utils_exceptions --> MaxRetriesException
    utils_exceptions --> RepoTypeNotSupported
    
    utils_predicates[utils.predicates] --> Predicates
    
    utils_flatten[utils.flatten] --> flatten
    
    scan_report_parsers[scan_report_parsers] --> AbstractFinding
    scan_report_parsers --> ReportParser
    scan_report_parsers --> OscapComplianceFinding
    scan_report_parsers --> OscapOVALFinding
    scan_report_parsers --> OscapFinding
    scan_report_parsers --> RuleInfo
    scan_report_parsers --> RuleInfoOVAL
    scan_report_parsers --> AnchoreCVEFinding
    
    hardening_manifest[hardening_manifest] --> HardeningManifest
    hardening_manifest --> source_values
    hardening_manifest --> get_source_keys_values
    
    apis[apis] --> VatAPI
    
    harbor[harbor] --> HarborRobot
    harbor --> HarborRobotPermissions
    harbor --> HarborProject
    harbor --> HarborRepository
    harbor --> HarborSystem
    
    abstract_artifacts[abstract_artifacts] --> AbstractArtifact
    abstract_artifacts --> AbstractFileArtifact
    
    artifacts[artifacts] --> S3Artifact
    artifacts --> HttpArtifact
    artifacts --> ContainerArtifact
    artifacts --> GithubArtifact
    
    file_parser[file_parser] --> AccessLogFileParser
    file_parser --> DockerfileParser
    file_parser --> SbomFileParser
    
    project[project] --> DsopProject
    
    vat_container_status[vat_container_status] --> sort_justifications
    
    package_parser[package_parser] --> NullPackage
    package_parser --> GoPackage
    package_parser --> RpmPackage
    package_parser --> PypiPackage
    package_parser --> NpmPackage
    package_parser --> RubyGemPackage
    package_parser --> DebianPackage
    package_parser --> ApkPackage
    paginated_request --> PaginatedRequest
    scanner_api_handlers --> Anchore
    test_mocks --> MockImage
    test_mocks --> MockOutput
    test_mocks --> MockPath
    test_mocks --> MockPopen
    test_mocks --> MockPaginatedRequest
    test_mocks --> MockSession
    test_mocks --> MockHarborRobot
    test_mocks --> MockHarborRobotPermissions
    test_mocks --> MockRuleInfo
    test_mocks --> MockRuleInfoOVAL
    test_mocks --> MockElement
    test_mocks --> MockElementTree
    test_mocks --> MockOscapFinding
    test_mocks --> MockOscapComplianceFinding
    test_mocks --> MockOscapOVALFinding
    test_mocks --> MockReportParser
    test_mocks --> TestUtils
    test_mocks --> MockHardeningManifest
    test_mocks --> MockVatAPI
    test_mocks --> MockResponse
    test_mocks --> MockGoodResponse






