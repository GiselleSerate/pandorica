pipeline {
    agent any
    environment {
        AUTOFOCUS_API_KEY_=credentials('AUTOFOCUS_API_KEY')
        AUTOFOCUS_API_KEY="${AUTOFOCUS_API_KEY_}"
    }
    stages {
        stage('Everything') {
            steps {
                sh 'docker build --tag pandorica:test .'
                sh '/usr/local/bin/docker-compose --file src/test/docker-compose.yaml run -e AUTOFOCUS_API_KEY=${AUTOFOCUS_API_KEY} --name testpandorica_con pandorica'
            }
        }
    }
    post {
        cleanup {
            sh 'docker rm -f testelastic_con'
            sh 'docker rm -f testpandorica_con'
        }
    }
}