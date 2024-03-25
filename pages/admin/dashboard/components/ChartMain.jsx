import { faker } from "@faker-js/faker";
import { BarChart, Bar, XAxis, YAxis, CartesianGrid, PieChart, Pie, Tooltip, Legend } from 'recharts';

const pieData = [
  { name: 'Open Rates', value: 234, color: '#82ca9d' },
  { name: 'Click Rates', value: 432, color: '#8884d8' },
];

const barData = [
  { name: 'Jan', OpenRate: 4000, ClickRate: 2400 },
  { name: 'Feb', OpenRate: 3000, ClickRate: 1398 },
  { name: 'Mar', OpenRate: 2000, ClickRate: 9800 },
  { name: 'Apr', OpenRate: 2780, ClickRate: 3908 },
  { name: 'May', OpenRate: 1890, ClickRate: 4800 },
  { name: 'Jun', OpenRate: 2390, ClickRate: 3800 },
  { name: 'Jul', OpenRate: 3490, ClickRate: 4300 },
];

const bars = [
  { dataKey: 'OpenRate', color: '#8884d8' },
  { dataKey: 'ClickRate', color: '#82ca9d' },
];

const ChartMain = () => {
  return (
    // <div className="widget-content">
    //   <Line options={options} data={data} />
    // </div>
    <div className="d-flex items-center">
      <div className="widget-content col-xl-5 col-md-4">
        <PieChart width={400} height={400}>
          <Pie
            dataKey="value"
            isAnimationActive={false}
            data={pieData}
            cx="50%"
            cy="50%"
            outerRadius={80}
            fill="#82ca9d"
            label
          />
          <Tooltip />
          <Legend />
        </PieChart>
      </div>
      <div className="widget-content col-xl-9 col-md-8">
        <BarChart width={600} height={300} data={barData}>
          <CartesianGrid strokeDasharray="3 3" />
          <XAxis dataKey="name" />
          <YAxis />
          <Tooltip />
          <Legend />
          {bars.map((bar, index) => (
            <Bar key={index} dataKey={bar.dataKey} fill={bar.color} />
          ))}
        </BarChart>
      </div>
    </div>

  );
};

export default ChartMain;
