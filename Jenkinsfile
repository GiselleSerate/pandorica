node {
    checkout scm

    docker.image('python:3.7-alpine3.9').inside() { b ->
        sh 'python -V'

        // Set up python.
        sh 'python -m venv venv'
        sh '. venv/bin/activate'
        // sh 'pip install --upgrade pip'
        sh 'pip install -r requirements.txt --no-cache-dir' // Here's a problem

        docker.image('sebp/elk:720').withRun('-p 9200:9200 -p 5601:5601 -v ~/data/backups:/var/backups -v ~/data/elastictest:/var/lib/elasticsearch --name testelk_con sebp/elk:latest') { c ->
            /* Wait until elk service is up */
            // sh 'while ! mysqladmin ping -h0.0.0.0 --silent; do sleep 1; done'
            sh 'while ! nc -z localhost 9200; do sleep 1; done'

            // Run tests
            sh '. venv/bin/activate'
            sh 'pytest -v src'
        }
    }

}