import React, { useState, useRef, useEffect } from "react";
import { Tab, TabList, TabPanel, Tabs } from "react-tabs";
import { makeLink } from "../../../../services/affiliate/offer";
import { ToastContainer, toast } from "react-toastify";
import { getOffers } from "../../../../services/affiliate/offer";
import MakeLink from './MakeLink'
import AffiliateLinks from './AffiliateLinks'
import SubAndName from './SubAndFrom'

const makeLinkModal = (props) => {
  const offer = props.dataSource

  const tabs = [
    {
      label: "Making Link",
      content: <MakeLink dataSource={offer} update={props.update} />,
    },
    {
      label: "Affiliate Links",
      content: <AffiliateLinks dataSource={offer} update={props.update} />,
    },
    {
      label: "Sub Lines & From Names",
      content: <SubAndName dataSource={offer} update={props.update} />,
    },
  ];

  const [tabIndex, setTabIndex] = useState(0);

  
  return (
    <div className="col-12 text-center mt-10">
      <Tabs
      className="tabs -underline-2 js-tabs"
      selectedIndex={tabIndex}
      onSelect={(index) => setTabIndex(index)}
    >
      <TabList className="tabs__controls row x-gap-40 y-gap-10 lg:x-gap-20">
        {tabs.map((tab, index) => (
          <Tab key={index} className="col-auto">
            <button className="tabs__button text-18 lg:text-16 text-light-1 fw-500 pb-5 lg:pb-0 js-tabs-button">
              {tab.label}
            </button>
          </Tab>
        ))}
      </TabList>

      <div className="tabs__content pt-30 js-tabs-content">
        {tabs.map((tab, index) => (
          <TabPanel
            key={index}
            className={`-tab-item-${index + 1} ${
              tabIndex === index ? "is-tab-el-active" : ""
            }`}
          >
            {tab.content}
          </TabPanel>
        ))}
      </div>
    </Tabs>
          <ToastContainer />
          </div>
  );
};

export default makeLinkModal;
