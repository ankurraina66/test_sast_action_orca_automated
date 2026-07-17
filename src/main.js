import * as core from '@actions/core';
import * as constants from './constants.js';
import client from './client.js';
import saclientutil from './saclientutil.js';
import asoc from './asoc.js';
import settings from './settings.js';
import statusChecker from './statusChecker.js';
import resultProcessor from './resultProcessor.js';

let sastScanId;
let scaScanId;

/*
 detect PR context
*/
const isPR = process.env.INPUT_IS_PR_SCAN === "true" || process.env.GITHUB_EVENT_NAME === "pull_request";
/*
 PR metadata from workflow inputs*/
const prNumber = process.env.INPUT_PR_NUMBER || "";
const branchName = process.env.INPUT_BRANCH_NAME || process.env.GITHUB_HEAD_REF || process.env.GITHUB_REF_NAME || "";
const repoName = process.env.INPUT_REPO_NAME || process.env.GITHUB_REPOSITORY || "";
const commitSha = process.env.GITHUB_SHA || "";
core.info(`GitHub Event: ${process.env.GITHUB_EVENT_NAME}`);
if (isPR) {
    core.info("Running SAST scan for Pull Request");
    core.info(`Repository: ${repoName}`);
    core.info(`PR Number: ${prNumber}`);
    core.info(`Branch: ${branchName}`);
    core.info(`Commit: ${commitSha}`);
}
else {
    core.info("Running SAST scan for Push/Manual trigger");
}

core.info(constants.DOWNLOADING_CLIENT);
saclientutil.downloadClient()
.then(() => {
    core.info(constants.GENERATING_IRX);
    return client.generateIrx();
})
.then((irx) => {
    if(irx.length > 1) {
        throw new Error(constants.ERROR_MULTIPLE_IRX);
    }
    else if(irx.length === 0) {
        throw new Error(constants.ERROR_NO_IRX);
    }
    
    core.info(constants.SUBMITTING_IRX);
    return asoc.runAnalysis(irx[0]);
})
.then((scanIds) => {
    core.info(constants.IRX_SUBMIT_SUCCESS);
    sastScanId = scanIds.sastScanId;
    scaScanId = scanIds.scaScanId;

    if(sastScanId) {
        core.info(`SAST Scan ID: ${sastScanId}`)
        core.info(`${settings.getScanUrl(sastScanId)}`);
    }

    if(scaScanId) {
        core.info(`SCA Scan ID: ${scaScanId}`)
        core.info(`${settings.getScanUrl(scaScanId)}`);
    }
	
	 /*
         PR metadata logging
    */
	if(isPR) {
            core.info(`PR scan detected`);
            core.info(`PR branch: ${process.env.GITHUB_HEAD_REF}`);
	}
    
    if(process.env.INPUT_WAIT_FOR_ANALYSIS !== 'true') {
        return null;
    }

    core.info(constants.WAIT_FOR_ANALYSIS);
    return statusChecker.waitForAnalysis(sastScanId, scaScanId);
})
.then((timedOut) => {
	if(timedOut === null) {
		return null;
	}
    if(timedOut) {
        core.warning(constants.ANALYSIS_TIMEOUT);
        return;
    }
    core.info(constants.GETTING_RESULTS);
    return resultProcessor.processScanResults(sastScanId, scaScanId);
})
.then(async(results) => {
	if(results === null) {
		return;
	}
    if(results) {
        core.info(results);
		//Generate markdown + html report
		if(sastScanId) {
			await asoc.getNonCompliantIssues(sastScanId, 'SAST', resultProcessor.getSastDownloadLink());
		}
		if(scaScanId) {
			await asoc.getNonCompliantIssues(scaScanId, 'SCA', resultProcessor.getScaDownloadLink());
		}
        core.info(constants.ANALYSIS_SUCCESS);
    }
})
.catch((error) => {
    if(error.response && error.response.body) {
        core.error(`Error: ${error.response.body}`);
    }
    core.setFailed(error);
})
