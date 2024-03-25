import { ToastContainer, toast } from "react-toastify";

const SubAndFrom = (props) => {
  const offer = props.dataSource
  
  return (
    <div className="col-12 text-center mt-10">
      <table className="table-3 -border-bottom col-12 line" >
        <tr >
          <td className="col-2 alignText-center">Subject Lines</td>
          <td>
            <div className="alignText-center">
              {offer.subjectLines?.split(",").map((link, i) => (
                <div key={i}>{link}</div>
              ))}
            </div>
          </td>
        </tr>
        <tr >
          <td className="col-2 alignText-center">From Names</td>
          <td>
            <div className="alignText-center">
              {offer.fromNames?.split(",").map((link, i) => (
                <div key={i}>{link}</div>
              ))}
            </div>
          </td>
        </tr>
      </table>
      
      <ToastContainer />
      </div>
  );
};

export default SubAndFrom;
