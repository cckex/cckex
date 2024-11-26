#include "ui/configtab.h"

#include <sstream>

#include <QLayout>
#include <QGroupBox>
#include <QLineEdit>
#include <QCheckBox>
#include <QFileDialog>
#include <QFormLayout>

#include "common.h"

namespace Ui {

ConfigTab::ConfigTab(QWidget *parent) : QWidget(parent)
{
	slot_reloadConfig();
}

void ConfigTab::slot_reloadConfig()
{

	json conf = get_config();

	if(layout != nullptr) delete layout;


	QGroupBox *wiresharkGroup = new QGroupBox(tr("Wireshark"));
	QFormLayout *wiresharkGroupLayout = new QFormLayout();

	QLineEdit *ws_tlsKeyfilePathLineEdit = new QLineEdit(wiresharkGroup);
	ws_tlsKeyfilePathLineEdit->setText(QString::fromStdString(conf["ws"]["tls_keylog_file"]));
	wiresharkGroupLayout->addRow(tr("TLS Key File:"), ws_tlsKeyfilePathLineEdit);

	QLineEdit *ws_signalKeyFileLineEdit = new QLineEdit(wiresharkGroup);
	ws_signalKeyFileLineEdit->setText(QString::fromStdString(conf["ws"]["signal_key_file"]));
	wiresharkGroupLayout->addRow(tr("Signal Key File"), ws_signalKeyFileLineEdit);

	wiresharkGroup->setLayout(wiresharkGroupLayout);


	QGroupBox *filterGroup = new QGroupBox(tr("Filter"));
	QFormLayout *filterGroupLayout = new QFormLayout();

	QLineEdit *filterSrcIpLineEdit = new QLineEdit();
	filterSrcIpLineEdit->setText(QString::fromStdString(conf["filter"]["src_ip"]));
	filterGroupLayout->addRow(tr("Source IP:"), filterSrcIpLineEdit);

	QLineEdit *filterDstIpLineEdit = new QLineEdit();
	filterDstIpLineEdit->setText(QString::fromStdString(conf["filter"]["dst_ip"]));
	filterGroupLayout->addRow(tr("Destination IP:"), filterDstIpLineEdit);

	QLineEdit *filterSrcPortLineEdit = new QLineEdit();
	filterSrcPortLineEdit->setText(QString::number((int)conf["filter"]["src_port"]));
	filterGroupLayout->addRow(tr("Source Port"), filterSrcPortLineEdit);

	QLineEdit *filterDstPortLineEdit = new QLineEdit();
	filterDstPortLineEdit->setText(QString::number((int)conf["filter"]["dst_port"]));
	filterGroupLayout->addRow(tr("Destination Port"), filterDstPortLineEdit);

/*	QLineEdit *filterLengthLineEdit = new QLineEdit();
	filterLengthLineEdit->setText(QString::number((int)conf["filter"]["length"]));
	filterGroupLayout->addRow(tr("Packet Length"), filterLengthLineEdit);*/
	
	filterGroup->setLayout(filterGroupLayout);

//////////////////////////
	QGroupBox *ccGroup = new QGroupBox(tr("Covert Channels"));
	QFormLayout *ccGroupLayout = new QFormLayout();

	for(auto elem : conf["cc"]["methods"]) {
		QCheckBox *ccCheckBox = new QCheckBox(ccGroup);

		if(elem["active"]) {
			ccCheckBox->setCheckState(Qt::Checked);
		} else {
			ccCheckBox->setCheckState(Qt::Unchecked);
		}
		
		std::stringstream sstream;
		sstream << "enable " << elem["name"] << " (idx=" << elem["index"] << "):";

		ccGroupLayout->addRow(QString::fromStdString(sstream.str()), ccCheckBox);
	}

	ccGroup->setLayout(ccGroupLayout);
	

	QGroupBox *cryptoGroup = new QGroupBox(tr("Payload Protection"));
	QFormLayout *cryptoGroupLayout = new QFormLayout();

	QCheckBox *enableCryptoCheckbox = new QCheckBox(cryptoGroup);
	enableCryptoCheckbox->setCheckState(Qt::Unchecked);
	enableCryptoCheckbox->setDisabled(true);
	cryptoGroupLayout->addRow(tr("Enable Payload Protection"), enableCryptoCheckbox);

	QLineEdit *cryptoMethodLineEdit = new QLineEdit(cryptoGroup);
	cryptoMethodLineEdit->setText(QString::fromStdString(conf["crypto"]["method"]));
	cryptoMethodLineEdit->setDisabled(true);
	cryptoGroupLayout->addRow(tr("Method"), cryptoMethodLineEdit);

	cryptoGroup->setLayout(cryptoGroupLayout);


	layout = new QVBoxLayout(this);
	layout->addWidget(wiresharkGroup);
	layout->addWidget(filterGroup);
	layout->addWidget(ccGroup);
	layout->addWidget(cryptoGroup);

	this->setLayout(layout);

}

ConfigTab::~ConfigTab()
{

}

}	// namespace Ui
