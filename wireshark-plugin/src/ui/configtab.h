
#pragma once

#include <QObject>
#include <QWidget>
#include <QVBoxLayout>

namespace Ui {

class ConfigTab : public QWidget {

	Q_OBJECT

 public:

	explicit ConfigTab(QWidget *parent = nullptr);
	~ConfigTab();

 public slots:

	void slot_reloadConfig();

 private:

	QVBoxLayout *layout = nullptr;
};

}	// namespace Ui
