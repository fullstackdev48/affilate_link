import ConnectDB from "../../../DB/connectDB";
import Offer from "../../../models/Affiliate";

export default async (req, res) => {
  await ConnectDB();

  const { id, offerName, offerID, affiliateName, payout, cap } = req.body;

  try {
    const createdOffer = await Offer.create({
      offerName: offerName,
      offerID: offerID,
      affiliateName: affiliateName,
      payout: payout,
      cap: cap,
    });

    if (!createdOffer) {
      return res.status(404).json({ error: "Offer Info not found" });
    }
    res.status(200).json({ success: true, message: "Offer Info created successfully" });
  } catch (error) {
    console.error("Error creating Offer Info:", error);
    res.status(500).json({
      success: false,
      error: "Internal server error",
    });
  }
};
