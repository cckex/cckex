
#pragma once

#include <QObject>
#include <QWidget>
#include <QTableWidget>

namespace Ui {

class MessageTab : public QWidget {

	Q_OBJECT

 public:

	explicit MessageTab(QWidget *parent = nullptr);
	~MessageTab();

 public slots:

	void slot_addMessage(int num, int type, QString text);

 private:

	QTableWidget *_messageTable;

};

}
