#include "ui/maintab.h"

#include <QPushButton>
#include <QFormLayout>

#include <epan/plugin_if.h>

#include "message_dissection/signalmessagecrypto.h"
#include "stats/cckex_stats.h"
#include "ui/uihandler.h"
#include "common.h"

namespace Ui {

MainTab::MainTab(QWidget *parent) : QTabWidget(parent) 
{
	QPushButton *resetKeyListButton = new QPushButton("Reset", this);
	connect(resetKeyListButton, &QPushButton::clicked,
		 UiHandler::getInstance(), &UiHandler::sig_resetKeyList);

	QPushButton *checkForKeysButton = new QPushButton("Check", this);
	connect(checkForKeysButton, &QPushButton::clicked,
		 [=]() { check_for_new_keys(); });

	QPushButton *applyFilterButton = new QPushButton("Apply", this);
	connect(applyFilterButton, &QPushButton::clicked,
		 this, &MainTab::slot_applyFilter);

	QPushButton *dumpTLSKeysButton = new QPushButton("Dump", this);
	connect(dumpTLSKeysButton, &QPushButton::clicked,
		 [=]() { dump_tls_keys_to_file(); });

	QPushButton *dumpStatsButton = new QPushButton("Dump", this);
	connect(dumpStatsButton, &QPushButton::clicked,
		 [=]() { ccStats::dump_to_csv_file(); });

	QFormLayout *layout = new QFormLayout(this);
	layout->addRow(tr("Reset Key List:"), resetKeyListButton);
	layout->addRow(tr("Check for Keys in CC Data:"), checkForKeysButton);
	layout->addRow(tr("Apply Filter:"), applyFilterButton);
	layout->addRow(tr("Dump TLS Keys to File: "), dumpTLSKeysButton);
	layout->addRow(tr("Dump Stats to CSV File: "), dumpStatsButton);

	this->setLayout(layout);
}

void MainTab::slot_applyFilter()
{
	plugin_if_apply_filter("tcp.reassembled.data or !tcp or !tcp.segment_data", TRUE);
	reset_keys();
	reset_ccdata();
	UiHandler::getInstance()->doReset();
}

MainTab::~MainTab()
{

}

}	// namespace Ui
