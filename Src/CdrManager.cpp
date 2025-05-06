#include "../Headers/CdrManager.h"
#include <QDir>
#include <QFileInfo>
#include <QDebug>
#include <QJsonDocument>
#include <QJsonArray>
#include <QDateTime>
#include <QCryptographicHash>

CdrManager::CdrManager(QObject *parent) : QObject(parent) {
    dockerManager = new DockerManager(this);
    cdrImageName = ""; // Initialized empty, user will select
    outputDir = QDir::tempPath() + "/cdr_output";
    
    // Make sure the output directory exists
    QDir().mkpath(outputDir);
}

CdrManager::~CdrManager() {
    delete dockerManager;
}

bool CdrManager::initialize() {
    if (!dockerManager->isDockerAvailable()) {
        qDebug() << "Docker is not available, cannot initialize CDR";
        return false;
    }
    
    // CDR cannot be initialized if image not selected
    if (cdrImageName.isEmpty()) {
        qDebug() << "CDR image not selected, please choose an image first";
        return false;
    }
    
    qDebug() << "Initializing CDR manager with image:" << cdrImageName;
    
    // Create temporary directory
    outputDir = QDir::tempPath() + "/cdr_output";
    QDir().mkpath(outputDir);
    
    qDebug() << "CDR initialized successfully with image:" << cdrImageName;
    qDebug() << "Output directory:" << outputDir;
    
    return true;
}

void CdrManager::setCdrImageName(const QString& imageName) {
    if (imageName.isEmpty()) {
        qDebug() << "Empty image name provided, cannot set";
        return;
    }
    
    cdrImageName = imageName;
    qDebug() << "CDR image set to:" << cdrImageName;
}

QString CdrManager::getCurrentImageName() const {
    return cdrImageName;
}

QStringList CdrManager::getAvailableCdrImages() const {
    // List of recommended CDR images - these images should be tested in real-world scenarios
    QStringList images;
    images << "dannybeckett/disarm:latest"         // DisARM CDR tool
          << "opendxl/opendxl-file-transfer-service:latest"  // OpenDXL file transfer service
          << "mintplaintext/pdf-redact-tools:latest" // PDF Redaction tools
          << "pdfcpu/pdfcpu:latest"                // PDF processing tool
          << "custom/cdr:latest";                  // Example custom image
    
    return images;
}

bool CdrManager::processFile(const QString& filePath) {
    // Image not selected, cannot process
    if (cdrImageName.isEmpty()) {
        qDebug() << "CDR image not selected, please choose an image first";
        return false;
    }

    QFileInfo fileInfo(filePath);
    if (!fileInfo.exists() || !fileInfo.isFile()) {
        qDebug() << "File does not exist: " << filePath;
        return false;
    }
    
    // Configure container name and properties
    QString containerConfig = "name=cdr_container,image=" + cdrImageName;
    
    // Start the container
    if (!dockerManager->startContainer(containerConfig)) {
        qDebug() << "Failed to start CDR container";
        return false;
    }
    
    // Copy the file to the container
    QString containerPath = "/input/" + fileInfo.fileName();
    if (!dockerManager->copyFileToContainer(filePath, containerPath)) {
        qDebug() << "Failed to copy file to container";
        dockerManager->stopContainer();
        return false;
    }
    
    // Run the CDR process - appropriate command for disarm image
    QString command = "disarm sanitize " + containerPath + " --output /output/";
    QString result = dockerManager->executeCommand(command);
    
    qDebug() << "CDR process result: " << result;
    
    // Generate the name for the processed file
    QString outputFileName = generateOutputFilename(filePath);
    
    // Copy the processed file from the container
    // disarm usually saves the file in the /output/ directory inside the container
    QString containerOutputPath = "/output/" + fileInfo.fileName() + "_sanitized";
    QString localOutputPath = outputDir + "/" + outputFileName;
    
    if (!dockerManager->copyFileFromContainer(containerOutputPath, localOutputPath)) {
        qDebug() << "Failed to copy processed file from container, trying alternative path";
        
        // Try an alternative file path
        containerOutputPath = "/output/" + fileInfo.fileName();
        
        if (!dockerManager->copyFileFromContainer(containerOutputPath, localOutputPath)) {
            qDebug() << "Failed to copy processed file from container";
            dockerManager->stopContainer();
            return false;
        }
    }
    
    // Stop the container
    dockerManager->stopContainer();
    
    qDebug() << "File processed successfully: " << localOutputPath;
    return true;
}

QString CdrManager::getCleanedFilePath(const QString& originalFilePath) {
    QFileInfo fileInfo(originalFilePath);
    return outputDir + "/" + generateOutputFilename(originalFilePath);
}

QString CdrManager::generateOutputFilename(const QString& inputFilePath) {
    QFileInfo fileInfo(inputFilePath);
    QString baseName = fileInfo.baseName();
    QString suffix = fileInfo.suffix();
    QString timestamp = QDateTime::currentDateTime().toString("yyyyMMdd_hhmmss");
    
    // Generate the cleaned file name
    return baseName + "_cleaned_" + timestamp + "." + suffix;
}

QJsonObject CdrManager::parseResults(const QString& resultData) {
    QJsonObject result;
    QJsonDocument doc = QJsonDocument::fromJson(resultData.toUtf8());
    
    if (doc.isNull() || !doc.isObject()) {
        qDebug() << "Invalid JSON result data";
        result["status"] = "error";
        result["message"] = "Invalid result data format";
        return result;
    }
    
    return doc.object();
}