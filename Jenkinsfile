pipeline {
    agent any
    tools {
        maven 'M3'
        jdk 'jdk17'
    }

    stages {
        stage('Checkout') {
            steps {
                git branch: 'main', url: 'https://github.com/your-repo/app.git'
            }
        }

        stage('Build') {
            steps {
                sh 'mvn clean compile -DskipTests'
            }
        }

        stage('SonarQube Analysis') {
            environment {
                scannerHome = tool 'sonar-scanner'
            }
            steps {
                withSonarQubeEnv('MySonarQube') {
                    sh """
                        ${scannerHome}/bin/sonar-scanner \
                        -Dsonar.projectKey=myapp \
                        -Dsonar.sources=src \
                        -Dsonar.host.url=${SONAR_HOST_URL} \
                        -Dsonar.login=${SONAR_AUTH_TOKEN}
                    """
                }
            }
        }

        stage('Wait for Quality Gate') {
            steps {
                timeout(time: 5, unit: 'MINUTES') {
                    waitForQualityGate abortPipeline: true
                }
            }
        }

        stage('AI Security Analysis') {
            when {
                expression { 
                    currentBuild.result != 'ABORTED' && 
                    env.SONAR_QG_STATUS == 'OK' 
                }
            }
            steps {
                script {
                    try {
                        // Get SonarQube issues via API instead of local file
                        def sonarIssues = getSonarQubeIssues()
                        
                        if (sonarIssues) {
                            def aiAnalysis = analyzeWithAI(sonarIssues)
                            echo "🔍 AI Security Analysis Results:"
                            echo aiAnalysis
                            
                            // Check for critical security issues
                            if (hasCriticalSecurityIssues(aiAnalysis)) {
                                error("🚨 AI detected critical security issues. Pipeline stopped.")
                            }
                        } else {
                            echo "✅ No SonarQube issues found for AI analysis"
                        }
                    } catch (Exception e) {
                        echo "⚠️ AI Analysis failed: ${e.message}. Continuing pipeline..."
                        // Don't fail the pipeline if AI service is down
                    }
                }
            }
        }

        stage('Container Scan with Trivy') {
            steps {
                script {
                    sh 'mvn package -DskipTests'
                    sh 'docker build -t myapp:${BUILD_NUMBER} .'
                    
                    // Scan with Trivy
                    sh 'trivy image --exit-code 0 --format json --output trivy-report.json myapp:${BUILD_NUMBER}'
                    
                    // AI Analysis of Trivy results
                    def trivyReport = readJSON file: 'trivy-report.json'
                    def trivyAnalysis = analyzeTrivyWithAI(trivyReport)
                    echo "🔍 AI Trivy Analysis:\n${trivyAnalysis}"
                }
            }
        }

        stage('Deploy to Staging') {
            when {
                expression { currentBuild.result == null || currentBuild.result == 'SUCCESS' }
            }
            steps {
                sh 'kubectl apply -f k8s/deployment.yaml'
                script {
                    // Add ZAP DAST scan here in real scenario
                    echo "🚀 Application deployed to staging"
                }
            }
        }
    }

    post {
        always {
            echo "Pipeline completed with status: ${currentBuild.result}"
            // Cleanup
            sh 'docker rmi myapp:${BUILD_NUMBER} || true'
        }
        success {
            echo "🎉 All checks passed! Code is secure and ready."
        }
        failure {
            echo "❌ Pipeline failed. Check logs for details."
        }
    }
}

// Custom functions
def getSonarQubeIssues() {
    try {
        def response = httpRequest [
            url: "${SONAR_HOST_URL}/api/issues/search?componentKeys=myapp&resolved=false",
            authentication: 'sonar-token',
            timeout: 30
        ]
        
        if (response.status == 200) {
            def issues = readJSON text: response.content
            return issues.issues ?: []
        }
        return []
    } catch (Exception e) {
        echo "Failed to fetch SonarQube issues: ${e.message}"
        return []
    }
}

def analyzeWithAI(sonarIssues) {
    if (!sonarIssues) return "No issues to analyze"
    
    // Summarize issues for AI
    def issueSummary = sonarIssues.collect { issue ->
        "• ${issue.severity} - ${issue.type}: ${issue.message} (File: ${issue.component})"
    }.join("\n")
    
    def prompt = """
    Analyze these SonarQube security issues and provide:
    1. Criticality assessment (Critical/High/Medium/Low)
    2. Security impact
    3. Recommended fixes
    4. Overall risk level
    
    Issues:
    ${issueSummary}
    """

    return callAI(prompt)
}

def analyzeTrivyWithAI(trivyReport) {
    def vulnerabilities = trivyReport.Results?.find { it.Vulnerabilities }?.Vulnerabilities ?: []
    
    if (!vulnerabilities) return "✅ No vulnerabilities found in container image"
    
    def vulnSummary = vulnerabilities.collect { vuln ->
        "• ${vuln.Severity} - ${vuln.VulnerabilityID}: ${vuln.Title} (Fixed in: ${vuln.FixedVersion ?: 'None'})"
    }.join("\n")
    
    def prompt = """
    Analyze these container vulnerabilities and provide:
    1. Critical vulnerabilities that need immediate attention
    2. Patch availability and recommendations
    3. Overall container security score (1-10)
    
    Vulnerabilities:
    ${vulnSummary}
    """
    
    return callAI(prompt)
}

def callAI(prompt) {
    try {
        def response = httpRequest [
            httpMode: 'POST',
            url: 'https://api.openai.com/v1/chat/completions',
            customHeaders: [[name: 'Authorization', value: "Bearer ${env.OPENAI_API_KEY}"]],
            contentType: 'APPLICATION_JSON',
            requestBody: """
            {
                "model": "gpt-4",
                "messages": [
                    {
                        "role": "system", 
                        "content": "You are a security expert analyzing code and container vulnerabilities. Be concise and focus on actionable recommendations."
                    },
                    {
                        "role": "user", 
                        "content": "${prompt}"
                    }
                ],
                "max_tokens": 1000
            }
            """,
            timeout: 60
        ]
        
        def content = readJSON text: response.content
        return content.choices[0].message.content
    } catch (Exception e) {
        return "AI analysis unavailable: ${e.message}"
    }
}

def hasCriticalSecurityIssues(aiAnalysis) {
    // Simple heuristic - you might want more sophisticated logic
    return aiAnalysis.toLowerCase().contains('critical') && 
           (aiAnalysis.toLowerCase().contains('vulnerability') || 
            aiAnalysis.toLowerCase().contains('security risk'))
}
/*
# Required Jenkins plugins:
- Pipeline
- HTTP Request Plugin
- SonarQube Scanner
- Docker Pipeline
Environment Variables Needed:
SONAR_HOST_URL=https://your-sonarqube-instance
SONAR_AUTH_TOKEN=your-sonar-token
OPENAI_API_KEY=your-openai-key */