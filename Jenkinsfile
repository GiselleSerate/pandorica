pipeline {
    agent any 
    stages {
        stage('Everything') { 
            steps {
                sh '/usr/local/bin/docker-compose up --build -f src/test/docker-compose.yml'
            }
        }
    }
}