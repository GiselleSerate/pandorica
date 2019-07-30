pipeline {
    agent any 
    stages {
        stage('Everything') { 
            steps {
                sh 'pwd'
                sh '/usr/local/bin/docker-compose --file src/test/docker-compose.yml up --build'
            }
        }
    }
}