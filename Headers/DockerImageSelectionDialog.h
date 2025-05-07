\
#ifndef DOCKERIMAGESELECTIONDIALOG_H
#define DOCKERIMAGESELECTIONDIALOG_H

#include <QDialog>
#include <QListWidgetItem>

// Forward declaration of the UI class
namespace Ui {
class DockerImageSelectionDialog;
}

class DockerImageSelectionDialog : public QDialog
{
    Q_OBJECT

public:
    explicit DockerImageSelectionDialog(QWidget *parent = nullptr);
    ~DockerImageSelectionDialog();
    QString getSelectedImageId() const;

private slots:
    void on_imageListWidget_itemDoubleClicked(QListWidgetItem *item);
    void on_okButton_clicked();
    void on_cancelButton_clicked();

private:
    Ui::DockerImageSelectionDialog *ui;
    QString selectedImageId;
    void populateImageList();
};

#endif // DOCKERIMAGESELECTIONDIALOG_H
