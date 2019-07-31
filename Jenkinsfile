pipeline {
    agent {
        docker {
            image 'paloaltonetworks/pandorica_test_elk:latest'
            alwaysPull true
        }
    }
    environment {
        AUTOFOCUS_API_KEY_=credentials('AUTOFOCUS_API_KEY')
        AUTOFOCUS_API_KEY="${AUTOFOCUS_API_KEY_}"
    }
    stages {
        stage('Everything') { 
            steps {
                // sh 'export AUTOFOCUS_API_KEY=${AUTOFOCUS_API_KEY}'
                sh 'echo $AUTOFOCUS_API_KEY'
                sh '/usr/local/bin/docker-compose --file src/test/docker-compose.yaml run -e AUTOFOCUS_API_KEY=${AUTOFOCUS_API_KEY} pandorica'
            }
        }
    }
}