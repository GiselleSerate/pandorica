pipeline {
    agent any 
    stages {
        stage('Everything') { 
            steps {
                sh 'echo $PWD'
                sh 'cd src/test'
                sh 'docker-compose '
            }
        }
    }
}