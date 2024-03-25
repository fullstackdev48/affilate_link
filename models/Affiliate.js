import mongoose from "mongoose";

const AffiliateSchema = new mongoose.Schema({
  offerName: {
    type: String,
    // required: true,
  },
  offerID: {
    type: String,
    required: true,
  },
  affiliateName: {
    type: String,
  },
  payout: {
    type: String,
  },
  cap: {
    type: String,
  },
  createLink: {
    type: String,
  },
  offerLink: {
    type: String,
  },
  affiliateLink: {
    type: String,
  },
  domain: {
    type: String,
  },
  offLinks: {
    type: String,
  },
  unsubLinks: {
    type: String,
  },
  privacyLinks: {
    type: String,
  },
  condLinks: {
    type: String,
  },
  telLinks: {
    type: String,
  },
  subjectLines: {
    type: String,
  },
  fromNames: {
    type: String,
  },
  resultLink: {
    type: String,
  }
});
const Affiliate = mongoose.models.Affiliate || mongoose.model("Affiliate", AffiliateSchema);

export default Affiliate;
