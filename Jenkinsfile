pipeline {
    agent any
    environment {
        AUTOFOCUS_API_KEY=credentials('AUTOFOCUS_API_KEY')
    }
    stages {
        stage('Everything') { 
            steps {
                sh '/usr/local/bin/docker-compose --file src/test/docker-compose.yaml up --build'
            }
        }
    }
}