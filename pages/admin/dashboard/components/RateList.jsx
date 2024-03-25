const RercentBooking = () => {
  const data = [
    {
      offerID: "suvom12324",
      email: "suvom1324@gmail.com",
      status: { color: "yellow-4", text: "yellow-3", label: "OpenRate" },
      createdAt: "04/03/2024 04:4",
    },
    {
      offerID: "husnakormoker12324",
      email: "husnakormoker1324@gmail.com",
      status: { color: "yellow-4", text: "blue-1", label: "ClickRate" },
      createdAt: "04/03/2024 05:34",
    },
    {
      offerID: "nikolay12324",
      email: "nikolay1324@gmail.com",
      status: { color: "yellow-4", text: "yellow-3", label: "OpenRate" },
      createdAt: "04/03/2024 06:44",
    },
    {
      offerID: "suvom12324",
      email: "suvom1324@gmail.com",
      status: { color: "yellow-4", text: "yellow-3", label: "OpenRate" },
      createdAt: "04/03/2024 07:42",
    },
    
  ];
  return (
    <div className="overflow-scroll scroll-bar-1 pt-30">
      <table className="table-2 col-12">
        <thead>
          <tr>
            <th>#</th>
            <th>OfferID</th>
            <th>Email</th>
            <th>Status</th>
            <th>Created At</th>
          </tr>
        </thead>
        <tbody>
          {data.map((row, index) => (
            <tr key={index}>
              <td>{index + 1}</td>
              <td>
                {row.offerID}
              </td>
              <td>{row.email}</td>
              <td>
                <div
                  className={`rounded-100 py-4 text-center col-12 text-14 fw-500 bg-${row.status.color} text-${row.status.text}`}
                >
                  {row.status.label}
                </div>
              </td>
              <td>{row.createdAt}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
};

export default RercentBooking;
