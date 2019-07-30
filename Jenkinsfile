pipeline {
    agent any 
    stages {
        stage('Everything') { 
            steps {
                sh '/usr/local/bin/docker-compose --file src/test/docker-compose.yaml up --build'
            }
        }
    }
}