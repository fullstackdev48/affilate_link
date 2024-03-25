import ChartSelect from "./ChartSelect";
import ChartMain from "./ChartMain";

const data = [
  {
    title: "Open Rate",
    amount: "234",
    description: "Total open rates",
    icon: "/img/dashboard/icons/1.svg",
  },
  {
    title: "Click Rate",
    amount: "432",
    description: "Total click rates",
    icon: "/img/dashboard/icons/2.svg",
  },
];

const DashboardCard = () => {
  return (
    <div>
      <div className="row y-gap-30">
        {data.map((item, index) => (
          <div key={index} className="col-xl-3 col-md-6">
            <div className="py-30 px-30 rounded-4 bg-white shadow-3">
              <div className="row y-gap-20 justify-between items-center">
                <div className="col-auto">
                  <div className="fw-500 lh-14">{item.title}</div>
                  <div className="text-26 lh-16 fw-600 mt-5">{item.amount}</div>
                  <div className="text-15 lh-14 text-light-1 mt-5">
                    {item.description}
                  </div>
                </div>
                <div className="col-auto">
                  <img src={item.icon} alt="icon" />
                </div>
              </div>
            </div>
          </div>
        ))}
      </div>
      <div className="row y-gap-30 pt-20 chart_responsive">
      <div className="col-xl-14 col-md-12">
        <div className="py-30 px-30 rounded-4 bg-white shadow-3">
          <div className="d-flex justify-between items-center">
            <h2 className="text-18 lh-1 fw-500">Earning Statistics</h2>
            <ChartSelect />
          </div>

          <div className="pt-30">
            <ChartMain />
          </div>
        </div>
      </div>
      </div>
    </div>
    
  );
};

export default DashboardCard;

