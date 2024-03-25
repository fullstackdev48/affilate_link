import React, { useState, useRef, useEffect } from "react";
import { createOffer, updateOffer } from "../../../../services/affiliate/offer";
import { ToastContainer, toast } from "react-toastify";

const offerUpdateModal = (props) => {
  const offer = props.dataSource

  const offerNameRef = useRef(null)
  const offerIDRef = useRef(null)
  const affiliateNameRef = useRef(null)
  const payoutRef = useRef(null)
  const capRef = useRef(null)

  useEffect(() => {
    if (offer) {
      offerNameRef.current.value = offer.offerName
      offerIDRef.current.value = offer.offerID
      affiliateNameRef.current.value = offer.affiliateName
      payoutRef.current.value = offer.payout
      capRef.current.value = offer.cap
    }
  }, [])

  const updateofferInfo = async (e) => {
    e.preventDefault()

    const offerName = offerNameRef.current.value
    const offerID = offerIDRef.current.value
    const affiliateName = affiliateNameRef.current.value
    const cap = capRef.current.value
    const payout = payoutRef.current.value

    if (offer) {
      const formData = {
        id: offer._id,
        offerName,
        offerID,
        affiliateName,
        cap,
        payout,
      }
      const res = await updateOffer(formData)
      if (res.success) {
        toast.success(res.message);
        props.update(props.current)
      }
    } else {
      const formData = {
        offerName,
        offerID,
        affiliateName,
        cap,
        payout,
      }
      const res = await createOffer(formData)
      if (res.success) {
        toast.success(res.message);
        props.update(props.current)
      }
    }
    
    props.closeModal()
  }
  
  return (
    <div className="col-12 text-center mt-10">
      <form>
        <div className="row y-gap-30 items-center">
          
              <div className="col-md-6">
                <div className="form-input ">
                  <input ref={offerNameRef} type="text" required />
                  <label className="lh-1 text-16 text-light-1">Offer Name</label>
                </div>
              </div>
              {/* End col-6 */}
              <div className="col-md-6">
                <div className="form-input ">
                  <input ref={offerIDRef} type="text" required />
                  <label className="lh-1 text-16 text-light-1">Offer ID</label>
                </div>
              </div>
              {/* End col-6 */}
              <div className="col-md-6">
                <div className="form-input ">
                  <input ref={affiliateNameRef} type="text" />
                  <label className="lh-1 text-16 text-light-1">
                    Affiliate Name
                  </label>
                </div>
              </div>
              <div className="col-md-6">
                <div className="form-input ">
                  <input ref={payoutRef} type="text" />
                  <label className="lh-1 text-16 text-light-1">
                    Payout
                  </label>
                </div>
              </div>
              <div className="col-md-6">
                <div className="form-input ">
                  <input ref={capRef} type="text" />
                  <label className="lh-1 text-16 text-light-1">
                    Cap
                  </label>
                </div>
              </div>
            </div>
            <div className="d-inline-block pt-30">
              <button
                className="button h-50 px-24 -dark-1 bg-blue-1 text-white"
                onClick={updateofferInfo}
              >
                {offer ? 'Update Offer Info' : 'Create Offer Info' } <div className="icon-arrow-top-right ml-15" />
              </button>
            </div>
          </form >
          <ToastContainer />
          </div>
  );
};

export default offerUpdateModal;
