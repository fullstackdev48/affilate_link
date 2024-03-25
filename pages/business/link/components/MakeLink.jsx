import React, { useState, useRef, useEffect } from "react";
import { makeLink } from "../../../../services/affiliate/offer";
import { ToastContainer, toast } from "react-toastify";
import { getOffers } from "../../../../services/affiliate/offer";

import { useRouter } from 'next/router'

let ElasticEmail = require('@elasticemail/elasticemail-client');
 



const makeLinkModal = (props) => {

  const router = useRouter()
  console.log('route===>', router)

  console.log('s')

  const offer = props.dataSource

  const createLinkRef = useRef(null)
  const offerLinkRef = useRef(null)
  const affiliateLinkRef = useRef(null)
  const domainRef = useRef(null)
  const resultLinkRef = useRef(null)

  const [recipient, setRecipient] = useState('')

  const [resultLink, setResultLink] = useState('')

  const getOffersInPage = async (page) => {
    const res = await getOffers(page)
    if (res.success) {
      console.log('offers===>', res)
      resultLinkRef.current.value = res.resultLink
    }
  }

  

  useEffect(() => {
    
    console.log('apiKey==>', process.env.NEXT_PUBLIC_ELASTIC_EMAIL_API_KEY)

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

  const handleRecipient = (e) => {
    e.preventDefault()

    setRecipient(e.target.value)
  }

  const sendEmail = async (e) => {
    e.preventDefault()

    const resultLink = resultLinkRef.current.value
    let defaultClient = ElasticEmail.ApiClient.instance;
 
    let apikey = defaultClient.authentications['apikey'];
    apikey.apiKey = process.env.NEXT_PUBLIC_ELASTIC_EMAIL_API_KEY

    let api = new ElasticEmail.EmailsApi()

    let email = ElasticEmail.EmailMessageData.constructFromObject({
      Recipients: [
        new ElasticEmail.EmailRecipient(recipient)
      ],
      Content: {
        Body: [
          ElasticEmail.BodyPart.constructFromObject({
            ContentType: "HTML",
            Content: resultLink
          })
        ],
        Subject: "Top Link",
        From: "rohelakormoker8@gmail.com"
      }
    });
 
    var callback = function(error, data, response) {
      if (error) {
        console.error(error);
        toast.error(error)
      } else {
        toast.success('Email is sent successfully.');
      }
    };
    api.emailsPost(email, callback);
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
                  <label className="lh-1 text-16 text-light-1">Offer ID</label>
                </div>
              </div>
              {/* End col-6 */}
              <div className="col-md-6">
                <div className="form-input ">
                  <input ref={affiliateLinkRef} type="text" />
                  <label className="lh-1 text-16 text-light-1">
                    Affiliate ID
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
          <div className="col-md-12 mt-30 mb-30 d-flex items-center">
            <div className="form-input col-md-7 mr-10">
              <input type="text" onChange={handleRecipient} value={recipient} />
              <label className="h-60 text-16 text-light-1">
                Recipient Email
              </label>
            </div>
            <button
              className="button h-60 px-24 -dark-1 bg-blue-1 text-white" onClick={sendEmail}
            >
              Submit <div className="icon-arrow-top-right ml-15" />
            </button>
            </div>
          <ToastContainer />
          </div>
  );
};

export default makeLinkModal;
