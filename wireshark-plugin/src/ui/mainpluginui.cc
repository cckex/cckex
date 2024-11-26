#include "ui/mainpluginui.h"

#include <QVBoxLayout>

#include "ui/cctab.h"
#include "ui/uihandler.h"
#include "ui/keysfiletab.h"
#include "ui/maintab.h"
#include "ui/messagetab.h"
#include "ui/configtab.h"

namespace Ui {

MainPluginUi::MainPluginUi(QWidget *parent) :
	QDialog(parent)
{
	
	this->resize(600, 400);

	_mainTabs = new QTabWidget(this);

	MainTab *mainTab = new MainTab(this);
	_mainTabs->addTab(mainTab, tr("Main"));

	CCTab *classicTab = new CCTab(this);
	_mainTabs->addTab(classicTab, tr("Classic CC"));

	connect(UiHandler::getInstance(), &UiHandler::sig_addRawClassicCCData,
		 classicTab, &CCTab::addRawData);
//	connect(UiHandler::getInstance(), &UiHandler::sig_newCChannelKeyEntryAdded,
//		 classicTab, &CCTab::addNewKeyEntry);

	CCTab *signalTab = new CCTab(this);
	_mainTabs->addTab(signalTab, tr("Signal CC"));

	connect(UiHandler::getInstance(), &UiHandler::sig_addRawSignalCCData,
		 signalTab, &CCTab::addRawData);
//	connect(UiHandler::getInstance(), &UiHandler::sig_newSignalKeyEntryAdded,
//		 signalTab, &CCTab::addNewKeyEntry);

	KeysFileTab *keysFileTab = new KeysFileTab(this);
	_mainTabs->addTab(keysFileTab, tr("Key File"));


	MessageTab *messageTab = new MessageTab(this);
	_mainTabs->addTab(messageTab, tr("Messages"));

	ConfigTab *configTab = new ConfigTab(this);
	_mainTabs->addTab(configTab, tr("Config"));

	QVBoxLayout *layout = new QVBoxLayout(this);
	layout->addWidget(_mainTabs);

	this->setLayout(layout);
}

MainPluginUi::~MainPluginUi()
{

}

}	// namespace ui
