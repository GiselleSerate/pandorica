node {
    checkout scm

    // docker.image('python:3.7-alpine3.9').inside() { b ->
    def app
    app = docker.build('pandorica', '.')
    app.inside() { b ->
        sh 'python3.7 -V'

        // Set up python.
        sh 'python3.7 -m venv .env'
        sh '. .env/bin/activate'

        // sh 'sudo apk --update add python py-pip openssl ca-certificates py-openssl wget'
        // sh 'sudo apk --update add --virtual build-dependencies libffi-dev openssl-dev python-dev py-pip build-base && pip install --upgrade pip && pip install -r requirements.txt && sudo apk del build-dependencies'

        // sh 'pip install --upgrade pip'
        // sh 'pip install -r requirements.txt --no-cache-dir' // Here's a problem

    }

    docker.image('sebp/elk:720').withRun('-p 9200:9200 -p 5601:5601 -v ~/data/backups:/var/backups -v ~/data/elastictest:/var/lib/elasticsearch --name testelk_con') { c ->
        sh 'echo um awkward'
    }
    // Wait what?
    app.inside() { d ->
        /* Wait until elk service is up */
        // sh 'while ! mysqladmin ping -h0.0.0.0 --silent; do sleep 1; done'
        sh 'while ! nc -z localhost 9200; do sleep 1; done'

        // Run tests
        sh '. .env/bin/activate'
        sh 'pytest -v src'        

    }

}