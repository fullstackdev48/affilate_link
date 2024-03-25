import dynamic from "next/dynamic";
import Seo from "../../components/common/Seo";
import Footer2 from "../../components/footer/footer-6";
import Header2 from "../../components/header/header-6";
import Hero3 from "../../components/hero/hero-2";
import BlockGuide from "../../components/home/home-2/BlockGuide";


const home_2 = () => {
  return (
    <>
      <Seo pageTitle="Affiliate" />
      <Header2 />
      <Hero3 />
      <section className="layout-pt-lg layout-pb-md">
        <div className="container">
          <div className="row y-gap-40 sm:y-gap-10 justify-between">
            <BlockGuide />
          </div>
        </div>
      </section>
      <Footer2 />
    </>
  );
};

export default dynamic(() => Promise.resolve(home_2), { ssr: false });
