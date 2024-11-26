
#pragma once

#include <QObject>
#include <QWidget>
#include <QTabWidget>

namespace Ui {

class MainTab : public  QTabWidget {
 
	Q_OBJECT

 public:

	explicit MainTab(QWidget *parent = nullptr);
	~MainTab();

 protected slots:

	void slot_applyFilter();	

};

}	// namespace Ui
