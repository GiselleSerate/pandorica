pipeline {
    agent {label 'sfnserver'}
    stages {
        stage('Parse') {
            steps {
                dir('/home/paloalto/pandorica_container/pandorica') {
                    sh '. .env/bin/activate'
                    sh '.env/bin/python src/notes_parser.py'
                }
            }
        }
        stage('Tag') {
            steps {
                dir('/home/paloalto/pandorica_container/pandorica') {
                    sh '. .env/bin/activate'
                    sh '.env/bin/python src/domain_processor.py'
                }
            }
        }
        stage('Calculate intervals') {
            steps {
                dir('/home/paloalto/pandorica_container/pandorica') {
                    sh '. .env/bin/activate'
                    sh '.env/bin/python src/interval_calculator.py'
                }
            }
        }
    }
}