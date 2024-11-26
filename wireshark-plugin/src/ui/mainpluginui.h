
#pragma once

#include <QObject>
#include <QDialog>
#include <QWidget>
#include <QTextEdit>
#include <QBoxLayout>
#include <QTabWidget>

namespace Ui {

class MainPluginUi : public QDialog {

	Q_OBJECT

 public:

	explicit MainPluginUi(QWidget *parent = nullptr);
	~MainPluginUi();

 private:

	QTabWidget *_mainTabs;

};

}	// namespace Ui
