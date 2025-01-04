pipeline {
    agent any
    
    environment {
        DOCKER_REGISTRY = 'harbor.pezl.local/project_mgmt'
    }
    
    parameters {
        choice(name: 'IMAGE_NAME', 
               choices: ['go-auth-service', 'nestjs-project-service', 'python-task-service', 'nextjs-front-service'], 
               defaultValue: 'go-auth-service')
               
        string(name: 'IMAGE_TAG', 
               defaultValue: 'latest', )

        choice(name: 'IMAGE_SEVERITY_LEVELS', 
               choices: ['UNKNOWN', 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL'], 
               defaultValue: 'HIGH')

        choice(name: 'VULNERABILITY_TYPES', 
               choices: ['os,library','os','library'], 
               defaultValue: 'os,library')
    }

    stages {
        stage('Checkout') {
            steps {
                git branch: 'main',
                    credentialsId: 'github-pezl05',
                    url: "https://github.com/Pezl05/${params.IMAGE_NAME}.git"
            }
        }
        
        stage('Build Image') {
            steps {
                sh "docker build -t $DOCKER_REGISTRY/${params.IMAGE_NAME}:${params.IMAGE_TAG} ."
            }
        }
        
        stage("Scan image"){
            steps {
                sh "trivy image --severity ${params.IMAGE_SEVERITY_LEVELS} --vuln-type ${params.VULNERABILITY_TYPES} --exit-code 1 $DOCKER_REGISTRY/${params.IMAGE_NAME}:${params.IMAGE_TAG}"
            }
        }
        
        stage('Push Image to Registry') {
            steps {
                withDockerRegistry(credentialsId: 'harbor-registy', url: "https://$DOCKER_REGISTRY") {
                    sh "docker push $DOCKER_REGISTRY/${params.IMAGE_NAME}:${params.IMAGE_TAG}"
                }
            }
        }
    }

    post {
        always {
            echo 'Cleaning up ...'
            sh "docker rmi -f $DOCKER_REGISTRY/${params.IMAGE_NAME}:${params.IMAGE_TAG}"
            cleanWs()
        }
    }
}
