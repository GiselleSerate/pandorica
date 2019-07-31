pipeline {
    agent any
    environment {
        AUTOFOCUS_API_KEY_=credentials('AUTOFOCUS_API_KEY')
        AUTOFOCUS_API_KEY="${AUTOFOCUS_API_KEY_}"
    }
    stages {
        stage('Everything') { 
            steps {
                sh '/usr/local/bin/docker-compose --file src/test/docker-compose.yaml run -e AUTOFOCUS_API_KEY=${AUTOFOCUS_API_KEY} pandorica'
            }
        }
    }
    post {
        cleanup {
            sh 'docker rm -f testelastic_con'
        }
    }
}