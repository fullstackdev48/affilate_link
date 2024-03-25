import ConnectDB from "../../../DB/connectDB";
import Offer from "../../../models/Affiliate";


export default async (req, res) => {
  await ConnectDB();

  const { id, offerName, offerID, affiliateName, payout, cap, createLink, offerLink, affiliateLink, domain } = req.body;
  const resultLink = domain + '/' + createLink

  try {
    const updatedOffer = await Offer.findByIdAndUpdate(id, {
      offerName: offerName,
      offerID: offerID,
      affiliateName: affiliateName,
      payout: payout,
      cap: cap,
      createLink,
      offerLink,
      affiliateLink,
      domain,
      resultLink
    });

    if (!updatedOffer) {
      return res.status(404).json({ error: "Offer not found" });
    }
    console.log(updatedOffer)
    res.status(200).json({ success: true, message: "Got link successfully", resultLink });
  } catch (error) {
    console.error("Error geting link:", error);
    res.status(500).json({
      success: false,
      error: "Internal server error",
    });
  }
};
