import React, { useState, useRef, useEffect } from "react";
import { makeLink } from "../../../../services/affiliate/offer";
import { ToastContainer, toast } from "react-toastify";
import { getOffers } from "../../../../services/affiliate/offer";

const makeLinkModal = (props) => {
  const offer = props.dataSource

  const createLinkRef = useRef(null)
  const offerLinkRef = useRef(null)
  const affiliateLinkRef = useRef(null)
  const domainRef = useRef(null)
  const resultLinkRef = useRef(null)

  const [resultLink, setResultLink] = useState('')

  const getOffersInPage = async (page) => {
    const res = await getOffers(page)
    if (res.success) {
      console.log('offers===>', res)
      resultLinkRef.current.value = res.resultLink
    }
  }

  useEffect(() => {
    
    if (offer) {
      createLinkRef.current.value = offer.createLink || ''
      offerLinkRef.current.value = offer.offerLink || ''
      affiliateLinkRef.current.value = offer.affiliateLink || ''
      domainRef.current.value = offer.domain || ''
      resultLinkRef.current.value = offer.resultLink || ''
    }
  }, [])

  const getLink = async (e) => {
    e.preventDefault()

    const createLink = createLinkRef.current.value
    const offerLink = offerLinkRef.current.value
    const affiliateLink = affiliateLinkRef.current.value
    const domain = domainRef.current.value
    const resultLink = resultLinkRef.current.value

    if (offer) {
      const formData = {
        id: offer._id,
        offerName: offer.offerName,
        offerID: offer.offerID,
        affiliateName: offer.affiliateName,
        payout: offer.payout,
        cap: offer.cap,
        createLink,
        offerLink,
        affiliateLink,
        domain,
        resultLink
      }
      const res = await makeLink(formData)
      if (res.success) {
        toast.success(res.message);
        // props.update(props.current)
        resultLinkRef.current.value = res.resultLink
      }
    } 
    // props.closeModal()
  }
  
  return (
    <div className="col-12 text-center mt-10">
      <form>
        <div className="row y-gap-30 items-center">
          
              <div className="col-md-6">
                <div className="form-input ">
                  <input ref={createLinkRef} type="text" required />
                  <label className="lh-1 text-16 text-light-1">Create Link</label>
                </div>
              </div>
              {/* End col-6 */}
              <div className="col-md-6">
                <div className="form-input ">
                  <input ref={offerLinkRef} type="text" required />
                  <label className="lh-1 text-16 text-light-1">Offer Link</label>
                </div>
              </div>
              {/* End col-6 */}
              <div className="col-md-6">
                <div className="form-input ">
                  <input ref={affiliateLinkRef} type="text" />
                  <label className="lh-1 text-16 text-light-1">
                    Affiliate Link
                  </label>
                </div>
              </div>
              <div className="col-md-6">
                <div className="form-input ">
                  <input ref={domainRef} type="text" />
                  <label className="lh-1 text-16 text-light-1">
                    Domain
                  </label>
                </div>
              </div>
              <div className="col-md-6">
                <div className="form-input ">
                  <input ref={resultLinkRef} type="text" />
                  <label className="lh-1 text-16 text-light-1">
                    Result Link
                  </label>
                </div>
              </div>
            </div>
            <div className="d-inline-block pt-30">
              <button
                className="button h-50 px-24 -dark-1 bg-blue-1 text-white"
                onClick={getLink}
              >
                Get Link <div className="icon-arrow-top-right ml-15" />
              </button>
            </div>
          </form >
          <ToastContainer />
          </div>
  );
};

export default makeLinkModal;
