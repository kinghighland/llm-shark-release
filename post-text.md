No longer rolling the dice against error codes — every root-cause diagnosis grounded in evidence.

As everyone knows, analyzing VoNR/VoLTE call failure reasons starts with having a PCAP.

But what if conditions are limited and you simply can't get one?

Rolling the dice or reading your fortune are both options — and honestly, they're not much worse than guessing blindly ~~

Of course, if you can describe the call process to an AI as thoroughly as possible, leveraging a case library combined with large-model reasoning, analysis isn't necessarily out of reach. If no matching case is found and the model relies entirely on generalization, accuracy will suffer; but if a case match is found, accuracy can improve significantly — and while it may not be as reliable as PCAP-based analysis, it's certainly more meaningful than rolling dice or fortune-telling!

Before reading on, tap the ··· menu in the top-right corner and hit the star to bookmark this.
Follow Deep-Sea FlowShark for a steady stream of updates.

---

**LLM-Shark Mobile** is a conversational signaling diagnostic tool. If you want to analyze a PCAP, scroll straight to the bottom. If you can't get a PCAP but still need to diagnose call failure reasons, don't hesitate — give LLM-Shark Mobile a try right now.

The screenshots in this article were taken on an Android tablet. On a phone's smaller screen the layout is more compact, but the functionality is identical.

After launching the app, you land directly on the main interface. Select the calling side, then check the characteristics of the call — for example, if there's a 183, check SIP 183; if no ringback tone was heard, leave SIP 180 Ringing unchecked. For all other call characteristics, fill them in based on the specific call you're analyzing. The example below shows a SIP 480 response code returned, a Detach and a Call-Forward during the call, and there's also a free-text field where you can add something like "4G context establishment failed."

*[Image]*

Tap the **Search Cases** button. If a case is found, tap **Enter Diagnosis** and wait for the LLM to finish responding.

*[Image]*

The AI's reply includes citation information for the reference cases. If the match confidence is low, the AI will flag that as well, noting that the analysis conclusion did not draw on any reference case — so be aware that the accuracy of the conclusion may be limited in that scenario.

Just like the desktop version, you can tap **Thinking Process** to review the AI's reasoning.

*[Image]*

Then, as usual, a follow-up question is in order. This time it's the question everyone wonders about:

> Setting aside the reference cases, think independently — are there any other possible causes?

*[Image]*

The AI sets the reference cases aside, analyzes entirely on its own, and proposes three possible causes.

*[Image]*

After the reply, you can again view the Thinking Process.

*[Image]*

Reading through the Thinking Process content is a great way to understand how the AI reasoned.

*[Image]*

Back on the main screen, tap the settings icon in the top-right corner to enter the LLM API parameter configuration page. Like all AI agent tools, BYOK mode requires three parameters: **Endpoint + Model + API Key**.

*[Image]*

After setting the three parameters, tap the **Verify** button to confirm the connection works. Since the model built into the app has a limited token quota and long-term availability cannot be guaranteed, it's recommended that you switch to your own model service as soon as possible. **SiliconFlow** is recommended — there's an invite link in the interface that takes you directly to their website.

Tap **About** on the main screen to see the software version information. If you need to analyze raw PCAP signaling, you'll need to download the desktop version from the Microsoft Store, which requires a subscription.

*[Image]*

---

**How to download the LLM-Shark Mobile installer?**

You'll need access to GitHub. Search for **llm-shark**, or go directly via the link below:

👉 https://github.com/kinghighland/llm-shark-release/releases/tag/1.0.8

*[Image]*

Once you've downloaded the APK, hand off the installation to your AI agent — WorkBuddy, for instance.