# IanOnPace post draft: UDS fuzzer lab

## LinkedIn (about 200 words)

I built a fake car computer, then wrote a program to break it.

It took 19 seconds to find 3 ways in.

Every car has ECUs (small computers) that answer diagnostic commands. That's how a mechanic's scan tool talks to your car. The language is called UDS.

A fuzzer throws thousands of slightly-wrong messages at an ECU and watches for anything strange. It works like a crash-test dummy for software.

Out of 5,000 test messages, it found:
1️⃣ A 2-byte message that crashed the ECU completely
2️⃣ A "secret" all-zero password that unlocked it (a leftover factory backdoor)
3️⃣ A hidden debug command that froze it for 3 seconds

The lesson: random junk found almost nothing. What worked was starting from *real* diagnostic messages and changing them a little at a time. Know the system, then push on its edges.

That's how I approach my day job running autonomous vehicles at Nuro, too. Most of the risk lives in the edge cases.

Everything ran on a simulated CAN bus. No real vehicles were harmed. 🏁

Code + write-up: [GitHub link]

#AutomotiveCybersecurity #CANbus #Fuzzing #ISO21434 #IanOnPace

---

## 60-second video script

- **0–5 s (hook, face cam):** "I broke a car computer 3 ways in 19 seconds. Here's how."
- **5–20 s (screen: ecu_sim.py):** "This is a fake ECU, the kind of computer that runs your brakes, doors and engine. It speaks UDS, the language mechanics' tools use."
- **20–40 s (screen: fuzzer running, the 3 NEW lines pop up):** "My fuzzer takes real diagnostic messages and mutates them. There's a crash. A backdoor password of all zeros. And a hidden command that freezes it."
- **40–55 s (face cam):** "Random junk found nothing. Smart, small changes found everything. Same reason we test edge cases in autonomous vehicles."
- **55–60 s:** "Simulation only, never on a real car. Code's in the bio. Follow IanOnPace."

## Before posting checklist

- [ ] Repo is public and the README renders
- [ ] Don't name or imply a real automaker or Nuro systems (this is a simulator)
- [ ] Check Nuro's social media / outside work policy before mentioning the job
- [ ] Post Tue–Thu morning
