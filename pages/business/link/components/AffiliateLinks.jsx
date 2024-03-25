import { ToastContainer, toast } from "react-toastify";

const AffiliateLinks = (props) => {
  const offer = props.dataSource

  return (
    <div className="col-12 text-center mt-10">
      <table className="table-3 -border-bottom col-12 line" >
        <tr >
          <td className="col-2 alignText-center">Offer Links</td>
          <td>
            <div className="alignText-center">
              {offer.offLinks?.split(",").slice(1, 100).map((link, i) => (
                <div key={i}>{link}</div>
              ))}
            </div>
          </td>
        </tr>
        <tr >
          <td className="col-2 alignText-center">Unsub Links</td>
          <td>
            <div className="alignText-center">
              {offer.unsubLinks?.split(",").slice(1, 100).map((link, i) => (
                <div key={i}>{link}</div>
              ))}
            </div>
          </td>
        </tr>
        <tr >
          <td className="col-2 alignText-center">Privacy Links</td>
          <td>
            <div className="alignText-center">
              {offer.privacyLinks?.split(",").slice(1, 100).map((link, i) => (
                <div key={i}>{link}</div>
              ))}
            </div>
          </td>
        </tr>
        <tr >
          <td className="col-2 alignText-center">Condition Links</td>
          <td>
            <div className="alignText-center">
              {offer.condLinks?.split(",").slice(1, 100).map((link, i) => (
                <div key={i}>{link}</div>
              ))}
            </div>
          </td>
        </tr>
        <tr >
          <td className="col-2 alignText-center">Telephone Links</td>
          <td>
            <div className="alignText-center">
              {offer.telLinks?.split(",").slice(1, 100).map((link, i) => (
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

export default AffiliateLinks;
