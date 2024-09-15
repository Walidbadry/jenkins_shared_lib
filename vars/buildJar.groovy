#!/usr/bin/env groovy

def call() {
    echo "building the application for branch $BRANCH_NAME"
    bat 'mvn package'
    //sh 'mvn package' //for linux 

}
