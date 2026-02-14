# VulnReach Complete System Flow

This document contains detailed flowcharts showing all execution paths and component interactions.

---

## 1. Main Pipeline Flow

```mermaid
flowchart TD
    Start([User Executes run_vulnreach.py]) --> ParseArgs[Parse CLI Arguments]
    ParseArgs --> CreateConfig[Create PipelineConfig]
    CreateConfig --> InitPipeline[Initialize VulnReachPipeline]
    InitPipeline --> RunAnalysis{Run Full Analysis}
    
    RunAnalysis --> Phase1[Phase 1: Static Analysis]
    RunAnalysis --> Phase2[Phase 2: Dynamic Analysis]
    RunAnalysis --> Phase3[Phase 3: Correlation]
    
    Phase1 --> P1_1[1.1 SBOM Generation]
    P1_1 --> P1_2[1.2 SCA Scanning]
    P1_2 --> P1_3[1.3 Exploitability]
    P1_3 --> P1_4[1.4 Taint Analysis]
    
    Phase2 --> P2_1[2.1 Container Detection]
    P2_1 --> P2_Check{Is Containerized?}
    P2_Check -->|No| Skip2[Skip Dynamic]
    P2_Check -->|Yes| P2_2[2.2 Runtime Analysis]
    
    Phase3 --> P3_1[3.1 Correlate Findings]
    P3_1 --> P3_2[3.2 Generate Verdicts]
    
    P1_4 --> Merge[Merge Results]
    Skip2 --> Merge
    P2_2 --> Merge
    P3_2 --> Merge
    
    Merge --> Output[Generate Outputs]
    Output --> RBOM[RBOM JSON/MD]
    Output --> Complete[complete_findings.json]
    Output --> HTML[report.html]
    
    RBOM --> End([Analysis Complete])
    Complete --> End
    HTML --> End
    
    style Start fill:#90EE90
    style End fill:#FFB6C1
    style Phase1 fill:#87CEEB
    style Phase2 fill:#DDA0DD
    style Phase3 fill:#F0E68C
```

---

## 2. SBOM Generation Flow

```mermaid
flowchart TD
    Start([SBOM Generation Request]) --> CheckSyft{Syft Installed?}
    CheckSyft -->|No| Error[Throw RuntimeError]
    CheckSyft -->|Yes| DetectLang[Detect Project Language]
    
    DetectLang --> LangCheck{Language?}
    LangCheck -->|Python| CountPy[Count .py files]
    LangCheck -->|Java| CountJava[Count .java files]
    LangCheck -->|JS| CountJS[Count .js/.ts files]
    LangCheck -->|Other| CountOther[Count other files]
    
    CountPy --> BuildCmd[Build Syft Command]
    CountJava --> BuildCmd
    CountJS --> BuildCmd
    CountOther --> BuildCmd
    
    BuildCmd --> RunSyft[Execute: syft target -o format=output]
    RunSyft --> CheckResult{Success?}
    
    CheckResult -->|No| Error
    CheckResult -->|Yes| Enhance[Enhance SBOM]
    
    Enhance --> GetDepTree[Get Dependency Tree]
    GetDepTree --> DepCheck{Tree Available?}
    
    DepCheck -->|No| ParseBasic[Parse Basic SBOM]
    DepCheck -->|Yes| EnrichPackages[Enrich Packages]
    
    EnrichPackages --> AddFields[Add Fields:<br/>- is_direct_dependency<br/>- dependency_depth<br/>- required_by]
    AddFields --> SaveSBOM[Save Enhanced SBOM]
    ParseBasic --> SaveSBOM
    
    SaveSBOM --> Parse[Parse Components]
    Parse --> Return([Return Component List])
    Error --> Fail([Return False])
    
    style Start fill:#90EE90
    style Return fill:#90EE90
    style Error fill:#FF6B6B
    style Fail fill:#FF6B6B
```

---

## 3. Static Taint Analysis Flow

```mermaid
flowchart TD
    Start([Taint Analysis Request]) --> Init[Initialize StaticTaintAnalyzer]
    Init --> FindFiles[Find All Python Files]
    
    FindFiles --> Loop{For Each File}
    Loop -->|Next File| ParseAST[Parse File to AST]
    Loop -->|Done| BuildFlows[Build Taint Flows]
    
    ParseAST --> VisitSource[SourceDetector.visit]
    ParseAST --> VisitSink[SinkDetector.visit]
    
    VisitSource --> DetectSources{Detect Sources}
    DetectSources -->|request.args| HTTPInput[HTTP_INPUT Source]
    DetectSources -->|os.environ| EnvVar[ENV_VAR Source]
    DetectSources -->|open| FileRead[FILE_READ Source]
    DetectSources -->|sys.argv| CLIArg[CLI_ARG Source]
    
    VisitSink --> DetectSinks{Detect Sinks}
    DetectSinks -->|execute| SQLSink[SQL_QUERY Sink]
    DetectSinks -->|eval| EvalSink[CODE_EVAL Sink]
    DetectSinks -->|system| CMDSink[OS_COMMAND Sink]
    DetectSinks -->|pickle.loads| DeserSink[DESERIALIZE Sink]
    
    HTTPInput --> StoreSources[Store Sources List]
    EnvVar --> StoreSources
    FileRead --> StoreSources
    CLIArg --> StoreSources
    
    SQLSink --> StoreSinks[Store Sinks List]
    EvalSink --> StoreSinks
    CMDSink --> StoreSinks
    DeserSink --> StoreSinks
    
    StoreSources --> Loop
    StoreSinks --> Loop
    
    BuildFlows --> MatchPairs{Match Source-Sink Pairs}
    MatchPairs --> CheckFunction{Same Function?}
    
    CheckFunction -->|Yes| HighConf[High Confidence Flow]
    CheckFunction -->|No| CheckFile{Same File?}
    
    CheckFile -->|Yes| MedConf[Medium Confidence Flow]
    CheckFile -->|No| LowConf[Low Confidence Flow]
    
    HighConf --> MapPackages[Map to Vulnerable Packages]
    MedConf --> MapPackages
    LowConf --> MapPackages
    
    MapPackages --> GroupByPkg[Group Flows by Package]
    GroupByPkg --> SaveFlows[Save static_taint_flows.json]
    SaveFlows --> Return([Return Flow Dictionary])
    
    style Start fill:#90EE90
    style Return fill:#90EE90
```

---

## 4. Dynamic Analysis Flow

```mermaid
flowchart TD
    Start([Dynamic Analysis Request]) --> CheckContainer{Use Container?}
    
    CheckContainer -->|Yes| ContainerPath[Container Dynamic Analyzer]
    CheckContainer -->|No| LocalPath[Local Dynamic Analyzer]
    
    ContainerPath --> BuildDockerCmd[Build Docker Command]
    BuildDockerCmd --> MountVolumes[Mount:<br/>- runtime_hooks<br/>- project_dir]
    MountVolumes --> RunContainer[docker run with runner.py]
    
    LocalPath --> FindHooks[Find runtime_hooks Directory]
    FindHooks --> BuildLocalCmd[Build Local Command]
    BuildLocalCmd --> RunLocal[python runner.py entrypoint]
    
    RunContainer --> Execute[Execute Application]
    RunLocal --> Execute
    
    Execute --> InstallHooks[Install Hooks BEFORE Execution]
    InstallHooks --> AuditHook[audit.install]
    InstallHooks --> ImportHook[imports.install]
    InstallHooks --> SinkHook[sinks.install]
    
    AuditHook --> RunApp[Run Target Application]
    ImportHook --> RunApp
    SinkHook --> RunApp
    
    RunApp --> CollectEvents{Collect Events}
    
    CollectEvents -->|Import Event| LogImport[Log Package Import]
    CollectEvents -->|Sink Event| LogSink[Log Sink Execution]
    CollectEvents -->|Audit Event| LogAudit[Log Audit Event]
    CollectEvents -->|Taint Event| LogTaint[Log Taint Flow]
    
    LogImport --> EventBuffer[Events Buffer]
    LogSink --> EventBuffer
    LogAudit --> EventBuffer
    LogTaint --> EventBuffer
    
    EventBuffer --> FlushEvents[Flush Events to JSON]
    FlushEvents --> CaptureStdout[Capture stdout]
    
    CaptureStdout --> ExtractJSON[Extract JSON from Output]
    ExtractJSON --> ParseCheck{Valid JSON?}
    
    ParseCheck -->|No| SearchLines[Search Lines for JSON]
    ParseCheck -->|Yes| ProcessEvents[Process Events]
    
    SearchLines --> ProcessEvents
    
    ProcessEvents --> TypeCheck{Event Type?}
    TypeCheck -->|import| CreateImportFinding[DynamicFinding: Import]
    TypeCheck -->|sink| CreateSinkFinding[DynamicFinding: Sink]
    TypeCheck -->|taint| CreateTaintFinding[DynamicFinding: Taint]
    TypeCheck -->|audit| CreateAuditFinding[DynamicFinding: Audit]
    
    CreateImportFinding --> Findings[Findings List]
    CreateSinkFinding --> Findings
    CreateTaintFinding --> Findings
    CreateAuditFinding --> Findings
    
    Findings --> Summary[Generate Summary]
    Summary --> SaveDynamic[Save dynamic_findings.json]
    SaveDynamic --> Return([Return Dynamic Results])
    
    style Start fill:#90EE90
    style Return fill:#90EE90
```

---

## 5. Correlation Engine Flow

```mermaid
flowchart TD
    Start([Correlation Request]) --> LoadInputs[Load Inputs]
    LoadInputs --> Vulns[Static Vulnerabilities]
    LoadInputs --> Taint[Taint Flows]
    LoadInputs --> Dynamic[Dynamic Findings]
    
    Vulns --> BuildContext[Build Runtime Context]
    Taint --> BuildContext
    Dynamic --> BuildContext
    
    BuildContext --> ExtractPackages[Extract Runtime Packages]
    BuildContext --> ExtractSinks[Extract Runtime Sinks]
    
    ExtractPackages --> PkgSet[runtime_packages Set]
    ExtractSinks --> SinkMap[runtime_sinks Map]
    
    PkgSet --> LoopVulns{For Each Vulnerability}
    SinkMap --> LoopVulns
    
    LoopVulns -->|Next Vuln| CheckLoaded{Package Loaded?}
    LoopVulns -->|Done| SaveResults[Save Correlated Findings]
    
    CheckLoaded --> DirectMatch{Direct Match?}
    DirectMatch -->|Yes| Loaded[runtime_loaded = true]
    DirectMatch -->|No| NormalizedMatch{Normalized Match?}
    
    NormalizedMatch -->|Yes| Loaded
    NormalizedMatch -->|No| ImportMap{Import Name Map?}
    
    ImportMap -->|Yes| Loaded
    ImportMap -->|No| NotLoaded[runtime_loaded = false]
    
    Loaded --> CheckSink{Sink Executed?}
    NotLoaded --> CheckSink
    
    CheckSink --> SearchSinks{Search runtime_sinks}
    SearchSinks -->|Found| SinkExec[sink_executed = true]
    SearchSinks -->|Not Found| SinkNotExec[sink_executed = false]
    
    SinkExec --> DetermineVerdict{Determine Verdict}
    SinkNotExec --> DetermineVerdict
    
    DetermineVerdict --> NoDynamic{Has Dynamic Data?}
    NoDynamic -->|No| VerdictPossible[Verdict: POSSIBLE<br/>Confidence: LOW]
    NoDynamic -->|Yes| LoadedAndSink{Loaded AND Sink?}
    
    LoadedAndSink -->|Yes| VerdictConfirmed[Verdict: CONFIRMED<br/>Confidence: HIGH<br/>Priority: CRITICAL/HIGH]
    LoadedAndSink -->|No| JustLoaded{Just Loaded?}
    
    JustLoaded -->|Yes| VerdictLikely[Verdict: LIKELY<br/>Confidence: MEDIUM<br/>Priority: by Severity]
    JustLoaded -->|No| VerdictUnlikely[Verdict: UNLIKELY<br/>Confidence: MEDIUM<br/>Priority: LOW]
    
    VerdictPossible --> BuildFinding[Build CorrelatedFinding]
    VerdictConfirmed --> BuildFinding
    VerdictLikely --> BuildFinding
    VerdictUnlikely --> BuildFinding
    
    BuildFinding --> AddEvidence[Add Evidence:<br/>- static_evidence<br/>- dynamic_evidence<br/>- correlation_reason]
    
    AddEvidence --> LoopVulns
    
    SaveResults --> CountVerdicts[Count by Verdict/Priority]
    CountVerdicts --> SaveJSON[Save correlated_findings.json]
    SaveJSON --> Return([Return Correlated Findings])
    
    style Start fill:#90EE90
    style Return fill:#90EE90
    style VerdictConfirmed fill:#FF6B6B
    style VerdictLikely fill:#FFD700
    style VerdictPossible fill:#87CEEB
    style VerdictUnlikely fill:#90EE90
```

---

## 6. Multi-Language Detection & Analysis

```mermaid
flowchart TD
    Start([Multi-Language Analysis]) --> DetectLang[ProjectLanguageDetector.detect_language]
    
    DetectLang --> ScanFiles[Scan Project Files]
    ScanFiles --> CountExts{Count Extensions}
    
    CountExts --> PyCount[.py files]
    CountExts --> JavaCount[.java files]
    CountExts --> JSCount[.js/.ts files]
    CountExts --> GoCount[.go files]
    CountExts --> CSCount[.cs files]
    CountExts --> PHPCount[.php files]
    
    PyCount --> CheckBuild{Check Build Files}
    JavaCount --> CheckBuild
    JSCount --> CheckBuild
    GoCount --> CheckBuild
    CSCount --> CheckBuild
    PHPCount --> CheckBuild
    
    CheckBuild --> PyBuild{requirements.txt?}
    CheckBuild --> JavaBuild{pom.xml?}
    CheckBuild --> JSBuild{package.json?}
    CheckBuild --> GoBuild{go.mod?}
    CheckBuild --> CSBuild{.csproj?}
    CheckBuild --> PHPBuild{composer.json?}
    
    PyBuild -->|Yes| LangPython[Language: Python]
    JavaBuild -->|Yes| LangJava[Language: Java]
    JSBuild -->|Yes| LangJS[Language: JavaScript]
    GoBuild -->|Yes| LangGo[Language: Go]
    CSBuild -->|Yes| LangCS[Language: C#]
    PHPBuild -->|Yes| LangPHP[Language: PHP]
    
    PyBuild -->|No| FallbackCount[Fallback: Max File Count]
    JavaBuild -->|No| FallbackCount
    JSBuild -->|No| FallbackCount
    GoBuild -->|No| FallbackCount
    CSBuild -->|No| FallbackCount
    PHPBuild -->|No| FallbackCount
    
    FallbackCount --> LangUnknown[Language: Unknown]
    
    LangPython --> RunAnalyzer{Run Analyzer}
    LangJava --> RunAnalyzer
    LangJS --> RunAnalyzer
    LangGo --> RunAnalyzer
    LangCS --> RunAnalyzer
    LangPHP --> RunAnalyzer
    
    RunAnalyzer -->|Python| PyAnalyzer[run_python_reachability_analysis]
    RunAnalyzer -->|Java| JavaAnalyzer[run_java_reachability_analysis]
    RunAnalyzer -->|JavaScript| JSAnalyzer[run_javascript_reachability_analysis]
    RunAnalyzer -->|Go| GoAnalyzer[run_go_reachability_analysis]
    RunAnalyzer -->|C#| CSAnalyzer[run_csharp_reachability_analysis]
    RunAnalyzer -->|PHP| PHPAnalyzer[run_php_reachability_analysis]
    
    PyAnalyzer --> PyFeatures[Features:<br/>- Call Graph<br/>- Route Extraction<br/>- Taint Analysis<br/>- Dynamic Hooks]
    JavaAnalyzer --> JavaFeatures[Features:<br/>- AST-grep Parsing<br/>- Maven/Gradle Analysis<br/>- Basic Reachability]
    JSAnalyzer --> JSFeatures[Features:<br/>- npm Analysis<br/>- Basic Reachability]
    GoAnalyzer --> GoFeatures[Features:<br/>- go.mod Analysis<br/>- Basic Reachability]
    CSAnalyzer --> CSFeatures[Features:<br/>- NuGet Analysis<br/>- Basic Reachability]
    PHPAnalyzer --> PHPFeatures[Features:<br/>- Composer Analysis<br/>- Basic Reachability]
    
    PyFeatures --> SaveReport[Save Language-Specific Report]
    JavaFeatures --> SaveReport
    JSFeatures --> SaveReport
    GoFeatures --> SaveReport
    CSFeatures --> SaveReport
    PHPFeatures --> SaveReport
    
    LangUnknown --> SkipAnalysis[Skip Language-Specific Analysis]
    
    SaveReport --> Return([Return Analysis Results])
    SkipAnalysis --> Return
    
    style Start fill:#90EE90
    style Return fill:#90EE90
    style LangPython fill:#3776AB
    style LangJava fill:#007396
    style LangJS fill:#F7DF1E
    style LangGo fill:#00ADD8
    style LangCS fill:#239120
    style LangPHP fill:#777BB4
```

---

## 7. RBOM Generation Flow

```mermaid
flowchart TD
    Start([RBOM Generation]) --> CreateBuilder[Create RBOMBuilder]
    
    CreateBuilder --> SetTarget[Set Target Info]
    SetTarget --> AddComponents[Add Components from SBOM]
    
    AddComponents --> LoopComponents{For Each Component}
    LoopComponents -->|Next| CreateComponent[Create RBOMComponent]
    LoopComponents -->|Done| AddVulns[Add Vulnerabilities]
    
    CreateComponent --> SetCompFields[Set Fields:<br/>- name<br/>- version<br/>- purl<br/>- licenses]
    SetCompFields --> LoopComponents
    
    AddVulns --> LoopVulns{For Each Vulnerability}
    LoopVulns -->|Next| MapComponent[Map to Component]
    LoopVulns -->|Done| AddExecution[Add Execution Summary]
    
    MapComponent --> FindCorr[Find Correlated Finding]
    FindCorr --> CorrExists{Correlation Exists?}
    
    CorrExists -->|Yes| ExtractVerdict[Extract:<br/>- verdict<br/>- confidence<br/>- priority]
    CorrExists -->|No| DefaultVerdict[Default:<br/>- POSSIBLE<br/>- LOW<br/>- by Severity]
    
    ExtractVerdict --> BuildRuntime[Build Runtime Evidence]
    DefaultVerdict --> BuildRuntime
    
    BuildRuntime --> DynamicCheck{Has Dynamic Data?}
    DynamicCheck -->|Yes| SetRuntime[Set:<br/>- package_loaded<br/>- sink_executed<br/>- execution_count]
    DynamicCheck -->|No| NoRuntime[runtime_evidence = null]
    
    SetRuntime --> BuildStatic[Build Static Evidence]
    NoRuntime --> BuildStatic
    
    BuildStatic --> TaintCheck{Has Taint Flows?}
    TaintCheck -->|Yes| SetTaint[Set taint_flows]
    TaintCheck -->|No| NoTaint[taint_flows = []]
    
    SetTaint --> BuildExploit[Build Exploit Evidence]
    NoTaint --> BuildExploit
    
    BuildExploit --> ExploitCheck{Has Exploits?}
    ExploitCheck -->|Yes| SetExploits[Set:<br/>- public_exploits<br/>- exploit_maturity]
    ExploitCheck -->|No| NoExploits[exploit_evidence = null]
    
    SetExploits --> CreateVulnReach[Create VulnerabilityReachability]
    NoExploits --> CreateVulnReach
    
    CreateVulnReach --> AddToVulns[Add to Vulnerabilities List]
    AddToVulns --> LoopVulns
    
    AddExecution --> CalcStats[Calculate Statistics:<br/>- total_components<br/>- total_vulnerabilities<br/>- by_verdict<br/>- by_priority]
    
    CalcStats --> SetAnalysisInfo[Set Analysis Info:<br/>- timestamp<br/>- duration<br/>- phases_completed]
    
    SetAnalysisInfo --> BuildRBOM[Build RBOM Object]
    BuildRBOM --> Serialize[Serialize RBOM]
    
    Serialize --> ToJSON[RBOMSerializer.to_json]
    Serialize --> ToMarkdown[RBOMSerializer.to_markdown]
    
    ToJSON --> SaveJSON[Save rbom.json]
    ToMarkdown --> SaveMD[Save rbom_report.md]
    
    SaveJSON --> Return([Return RBOM])
    SaveMD --> Return
    
    style Start fill:#90EE90
    style Return fill:#90EE90
```

---

## 8. AI Analysis Flow

```mermaid
flowchart TD
    Start([AI Analysis Request]) --> CheckConfig{AI Configured?}
    
    CheckConfig -->|No| SkipAI[Skip AI Analysis]
    CheckConfig -->|Yes| LoadData[Load Analysis Data]
    
    LoadData --> Integrate[Integrate Data Sources]
    Integrate --> VulnData[Vulnerability Data]
    Integrate --> ReachData[Reachability Data]
    Integrate --> ExploitData[Exploitability Data]
    
    VulnData --> MergeData[Merge Data by Package/CVE]
    ReachData --> MergeData
    ExploitData --> MergeData
    
    MergeData --> LoopVulns{For Each Vulnerability}
    LoopVulns -->|Next| BuildPrompt[Build AI Prompt]
    LoopVulns -->|Done| GenerateSummary[Generate AI Summary]
    
    BuildPrompt --> PromptParts[Include:<br/>- CVE details<br/>- Severity<br/>- Reachability status<br/>- Exploit availability<br/>- Code context]
    
    PromptParts --> SelectProvider{Select Provider}
    SelectProvider -->|OpenAI| CallOpenAI[Call OpenAI API]
    SelectProvider -->|Anthropic| CallAnthropic[Call Anthropic API]
    SelectProvider -->|Local| CallLocal[Call Local LLM]
    
    CallOpenAI --> ParseResponse[Parse LLM Response]
    CallAnthropic --> ParseResponse
    CallLocal --> ParseResponse
    
    ParseResponse --> ExtractFields[Extract:<br/>- Priority score<br/>- Recommendation<br/>- Remediation steps<br/>- Short-term actions<br/>- Long-term actions<br/>- Risk assessment]
    
    ExtractFields --> CreateResult[Create AIAnalysisResult]
    CreateResult --> LoopVulns
    
    GenerateSummary --> CalcScore[Calculate Overall Security Score]
    CalcScore --> TopRecs[Identify Top Recommendations]
    TopRecs --> Trends[Analyze Security Trends]
    Trends --> Compliance[Generate Compliance Considerations]
    
    Compliance --> CreateSummary[Create AIAnalysisSummary]
    CreateSummary --> SaveAI[Save ai_analysis.json]
    
    SkipAI --> Return([Return Results])
    SaveAI --> Return
    
    style Start fill:#90EE90
    style Return fill:#90EE90
    style CallOpenAI fill:#10A37F
    style CallAnthropic fill:#D4A574
    style CallLocal fill:#4A90E2
```

---

## 9. Reachability Scoring Engine

```mermaid
flowchart TD
    Start([Reachability Engine]) --> LoadSemgrep[Load semgrep.json]
    LoadSemgrep --> LoadRoutes[Load routes.json]
    
    LoadRoutes --> LoopFindings{For Each SAST Finding}
    LoopFindings -->|Next| ExtractInfo[Extract:<br/>- rule_id<br/>- file<br/>- line<br/>- sink_function<br/>- severity]
    LoopFindings -->|Done| SaveResults[Save Results]
    
    ExtractInfo --> FindHandler[Find Enclosing Handler]
    FindHandler --> DetectLang{File Extension?}
    
    DetectLang -->|.py| PyHandler[Parse Python Functions]
    DetectLang -->|.js| JSHandler[Parse JavaScript Functions]
    DetectLang -->|.java| JavaHandler[Parse Java Methods]
    
    PyHandler --> CheckLine{Line in Function?}
    JSHandler --> CheckLine
    JavaHandler --> CheckLine
    
    CheckLine -->|Yes| HandlerFound[handler = function_name]
    CheckLine -->|No| NoHandler[handler = null]
    
    HandlerFound --> MatchRoute[Match Handler to Route]
    NoHandler --> MatchRoute
    
    MatchRoute --> SearchRoutes{Search routes.json}
    SearchRoutes -->|Match File| CheckHandler{Handler Match?}
    SearchRoutes -->|No Match| NoRoute[route = null]
    
    CheckHandler -->|Yes| RouteFound[route = route_obj]
    CheckHandler -->|No| NoRoute
    
    RouteFound --> ComputeScore[Compute Reachability Score]
    NoRoute --> ComputeScore
    
    ComputeScore --> BaseScore[Base Score = 0.0]
    BaseScore --> AddHandler{Has Handler?}
    
    AddHandler -->|Yes| Plus04[+ 0.4]
    AddHandler -->|No| Plus02[+ 0.2]
    
    Plus04 --> AddRoute{Has Route?}
    Plus02 --> AddRoute
    
    AddRoute -->|Yes| Plus03[+ 0.3]
    AddRoute -->|No| NoRoutePlus[+ 0.0]
    
    Plus03 --> AddTaint{Has Taint Hint?}
    NoRoutePlus --> AddTaint
    
    AddTaint -->|Yes| Plus02T[+ 0.2]
    AddTaint -->|No| NoTaintPlus[+ 0.0]
    
    Plus02T --> AddSeverity{Severity?}
    NoTaintPlus --> AddSeverity
    
    AddSeverity -->|CRITICAL/HIGH| Plus01[+ 0.1]
    AddSeverity -->|MEDIUM| Plus005[+ 0.05]
    AddSeverity -->|LOW| NoSevPlus[+ 0.0]
    
    Plus01 --> FinalScore[Final Score = min(sum, 1.0)]
    Plus005 --> FinalScore
    NoSevPlus --> FinalScore
    
    FinalScore --> FilterScore{Score >= 0.4?}
    FilterScore -->|No| LoopFindings
    FilterScore -->|Yes| BuildReason[Build Reason String]
    
    BuildReason --> CreateFinding[Create ReachabilityFinding]
    CreateFinding --> LoopFindings
    
    SaveResults --> SaveJSON[Save sink_handler_reachability.json]
    SaveJSON --> Return([Return Findings])
    
    style Start fill:#90EE90
    style Return fill:#90EE90
```

---

## 10. Configuration Loading Flow

```mermaid
flowchart TD
    Start([Configuration Request]) --> GetLoader[get_config_loader]
    GetLoader --> SingletonCheck{Loader Exists?}
    
    SingletonCheck -->|Yes| ReturnExisting[Return Existing Loader]
    SingletonCheck -->|No| CreateNew[Create ConfigLoader]
    
    CreateNew --> FindConfig[Find Config File]
    FindConfig --> CheckHome{~/.vulnreach/config/creds.yaml exists?}
    
    CheckHome -->|Yes| LoadYAML[Load YAML File]
    CheckHome -->|No| UseDefaults[Use Default Config]
    
    LoadYAML --> ParseYAML[Parse YAML]
    ParseYAML --> ValidateSchema{Valid Schema?}
    
    ValidateSchema -->|No| LogWarning[Log Warning]
    ValidateSchema -->|Yes| ExtractProviders[Extract Providers]
    
    LogWarning --> UseDefaults
    
    ExtractProviders --> CheckProviders{Has Providers?}
    CheckProviders -->|Yes| SetProviders[Set Provider Configs]
    CheckProviders -->|No| NoProviders[providers = []]
    
    SetProviders --> BuildConfig[Build VulnReachConfig]
    NoProviders --> BuildConfig
    UseDefaults --> BuildConfig
    
    BuildConfig --> CheckEnv[Check Environment Variables]
    CheckEnv --> OverrideCheck{Env Vars Set?}
    
    OverrideCheck -->|Yes| Override[Override Config with Env]
    OverrideCheck -->|No| FinalConfig[Finalize Config]
    
    Override --> EnvVars[Apply:<br/>- LLM_HOST<br/>- LLM_TIMEOUT<br/>- VULNREACH_AI_MOCK<br/>- etc.]
    
    EnvVars --> FinalConfig
    FinalConfig --> CacheConfig[Cache Configuration]
    CacheConfig --> ReturnExisting
    
    ReturnExisting --> Return([Return Config])
    
    style Start fill:#90EE90
    style Return fill:#90EE90
```

---

## 11. Error Handling & Recovery Paths

```mermaid
flowchart TD
    Start([Operation Start]) --> TryBlock[Try: Execute Operation]
    
    TryBlock --> Success{Success?}
    Success -->|Yes| Return([Return Result])
    Success -->|No| CatchError[Catch Exception]
    
    CatchError --> ErrorType{Exception Type?}
    
    ErrorType -->|ToolNotFound| CheckOptional{Tool Optional?}
    ErrorType -->|FileNotFound| CheckCritical{Critical File?}
    ErrorType -->|Timeout| CheckRetry{Retry Available?}
    ErrorType -->|JSONDecodeError| TryFallback{Fallback Parser?}
    ErrorType -->|Other| LogError[Log Error]
    
    CheckOptional -->|Yes| WarnSkip[Warn & Skip Feature]
    CheckOptional -->|No| RaiseError[Raise RuntimeError]
    
    CheckCritical -->|Yes| RaiseError
    CheckCritical -->|No| WarnSkip
    
    CheckRetry -->|Yes| DecrementRetry[Decrement Retry Count]
    CheckRetry -->|No| WarnSkip
    
    DecrementRetry --> RetryOp[Retry Operation]
    RetryOp --> TryBlock
    
    TryFallback -->|Yes| UseFallback[Use Fallback Parser]
    TryFallback -->|No| WarnSkip
    
    UseFallback --> PartialSuccess[Partial Success]
    PartialSuccess --> Return
    
    WarnSkip --> ContinuePartial[Continue with Partial Results]
    ContinuePartial --> Return
    
    LogError --> RaiseError
    RaiseError --> Fail([Operation Failed])
    
    style Start fill:#90EE90
    style Return fill:#90EE90
    style Fail fill:#FF6B6B
```

---

## 12. Complete System Component Interaction

```mermaid
flowchart LR
    subgraph Entry["Entry Layer"]
        CLI[CLI<br/>run_vulnreach.py]
        MainCLI[Main CLI<br/>cli.py]
    end
    
    subgraph Config["Configuration"]
        ConfigLoader[Config Loader]
        ConfigFile[~/.vulnreach/<br/>config/creds.yaml]
        EnvVars[Environment<br/>Variables]
    end
    
    subgraph Pipeline["Pipeline Layer"]
        Orchestrator[VulnReachPipeline]
        ContainerDet[Container<br/>Detector]
    end
    
    subgraph Tools["External Tools"]
        Syft[Syft<br/>SBOM]
        Trivy[Trivy<br/>SCA]
        Semgrep[Semgrep<br/>SAST]
        Docker[Docker<br/>Runtime]
        SearchSploit[SearchSploit<br/>Exploits]
    end
    
    subgraph Analyzers["Analysis Layer"]
        TaintAnal[Taint<br/>Analyzer]
        DynAnal[Dynamic<br/>Analyzer]
        ReachEng[Reachability<br/>Engine]
        ExploitAnal[Exploitability<br/>Analyzer]
        AIAnal[AI<br/>Analyzer]
    end
    
    subgraph Correlation["Correlation Layer"]
        Correlator[Finding<br/>Correlator]
        EventMatcher[Event<br/>Matcher]
        PkgResolver[Package<br/>Resolver]
    end
    
    subgraph Output["Output Layer"]
        RBOMGen[RBOM<br/>Generator]
        Reporter[HTML<br/>Reporter]
        Serializer[JSON/MD<br/>Serializer]
    end
    
    subgraph Storage["Storage"]
        SBOMJ[sbom.json]
        TrivyJ[trivy_output.json]
        TaintJ[static_taint_flows.json]
        DynJ[dynamic_findings.json]
        CorrJ[correlated_findings.json]
        CompleteJ[complete_findings.json]
        RBOMJ[rbom.json]
        RBOMD[rbom_report.md]
    end
    
    CLI --> MainCLI
    MainCLI --> ConfigLoader
    ConfigLoader --> ConfigFile
    ConfigLoader --> EnvVars
    
    MainCLI --> Orchestrator
    Orchestrator --> ContainerDet
    
    Orchestrator --> Syft
    Orchestrator --> Trivy
    Orchestrator --> Semgrep
    
    Syft --> SBOMJ
    Trivy --> TrivyJ
    
    Orchestrator --> TaintAnal
    Orchestrator --> DynAnal
    Orchestrator --> ReachEng
    Orchestrator --> ExploitAnal
    
    ContainerDet --> DynAnal
    DynAnal --> Docker
    
    ExploitAnal --> SearchSploit
    
    TaintAnal --> TaintJ
    DynAnal --> DynJ
    
    TaintJ --> Correlator
    DynJ --> Correlator
    TrivyJ --> Correlator
    
    Correlator --> EventMatcher
    Correlator --> PkgResolver
    Correlator --> CorrJ
    
    CorrJ --> AIAnal
    ConfigLoader --> AIAnal
    AIAnal --> Orchestrator
    
    Orchestrator --> RBOMGen
    RBOMGen --> RBOMJ
    RBOMGen --> RBOMD
    
    Orchestrator --> Reporter
    Reporter --> CompleteJ
    
    Orchestrator --> Serializer
    
    style Entry fill:#E8F4F8
    style Config fill:#FFF4E6
    style Pipeline fill:#E8F5E9
    style Tools fill:#F3E5F5
    style Analyzers fill:#E3F2FD
    style Correlation fill:#FFF3E0
    style Output fill:#F1F8E9
    style Storage fill:#EEEEEE
```

---

## Legend

### Node Colors
- 🟢 **Green** - Start/End points, Success states
- 🔵 **Blue** - Processing/Analysis phases
- 🟡 **Yellow** - Decision points
- 🔴 **Red** - Error states, Critical priorities
- 🟣 **Purple** - External tools/services

### Flow Directions
- **Top-Down (TD)** - Sequential processing
- **Left-Right (LR)** - Component interactions
- **Subgraphs** - Logical groupings

### Decision Diamonds
- `{Condition?}` - Yes/No branches
- `{Switch}` - Multiple outcome branches

---

**Document Maintenance:**
- Update when new flows are added
- Review during architecture changes
- Validate with actual code during refactoring

**Last Updated:** February 14, 2026

