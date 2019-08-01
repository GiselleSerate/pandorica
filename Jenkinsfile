pipeline {
    agent any
    stages {
        stage('Setup') {
            steps {
                sh 'source .env/bin/activate'
            }
        }
        stage('Parse') {
            steps {
                sh 'python notes_parser.py'
            }
        }
        stage('Tag') {
            steps {
                sh 'python domain_processor.py'
            }
        }
        stage('Aggregate') {
            steps {
                sh 'python aggregator.py'
            }
        }
    }
}