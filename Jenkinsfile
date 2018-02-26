@Library("dst-shared") _

obsBuildPipeline {
    product = "shs-cn,shs-ncn"
    productStream = "slingshot-host-software"
    timeout = 30
    masterBranch = "integration"
    exportPrep = "obsExportPrep.sh"
    recv_triggers = ["cxi-driver-built"]
    manifestGen = "true"
    numToKeepStr= 40
}
