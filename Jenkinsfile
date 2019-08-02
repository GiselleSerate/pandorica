pipeline {
    agent {label 'sfnserver'}
    stages {
        stage('Parse') {
            steps {
                dir('/home/paloalto/pandorica_container/pandorica') {
                    sh '. .env/bin/activate'
                    sh 'python -V'
                    sh 'python3 -V'
                    sh 'python src/notes_parser.py'
                }
            }
        }
        stage('Tag') {
            steps {
                dir('/home/paloalto/pandorica_container/pandorica') {
                    sh '. .env/bin/activate'
                    sh 'python src/domain_processor.py'
                }
            }
        }
        stage('Calculate intervals') {
            steps {
                dir('/home/paloalto/pandorica_container/pandorica') {
                    sh '. .env/bin/activate'
                    sh 'python src/interval_calculator.py'
                }
            }
        }
    }
}