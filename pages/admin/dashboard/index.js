import Seo from "../../../components/common/Seo";
import DashTab from "./components/DashTab";
import Sidebar from "../common/Sidebar";
import Header from "../../../components/header/dashboard-header";

import Link from "next/link";
// import RercentBooking from "./components/RercentBooking";
import Footer from "../common/Footer";

const index = () => {
  return (
    <>
      <Seo pageTitle="Dashboard" />

      <div className="header-margin"></div>

      <Header />

      <div className="dashboard">
        <div className="dashboard__sidebar bg-white scroll-bar-1">
          <Sidebar />
        </div>

        <div className="dashboard__main">
          <div className="dashboard__content bg-light-2">
            <div className="row y-gap-20 justify-between items-end pb-60 lg:pb-40 md:pb-32">
              <div className="col-12">
                <h1 className="text-30 lh-14 fw-600">Dashboard</h1>
                <div className="text-15 text-light-1">
                  Administrator / Dashboard
                </div>
              </div>
            </div>

            <DashTab />
            </div>

            <Footer />
          </div>
        </div>
    </>
  );
};

export default index;
