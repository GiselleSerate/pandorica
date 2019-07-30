pipeline {
    agent any 
    stages {
        stage('Everything') { 
            steps {
                sh 'echo $PWD'
                sh 'cd src/test'
                sh '/usr/local/bin/docker-compose up --build'
            }
        }
    }
}