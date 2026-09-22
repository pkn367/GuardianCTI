# Review-1 execution plan

Where you are once this repository runs on your machine: roughly **55–60% of
total implementation**. What follows takes you to 80%.

## Completion status

| Component | State | Remaining work |
|---|---|---|
| Control catalogue (19 checks, 4 frameworks) | done | add checks as you find gaps |
| AWS collectors (7 services) | done | needs one run against the real lab account |
| CTI integration (KEV, NVD, ATT&CK) | done | run once online to replace the cached fallback |
| Risk model + posture scoring | done | — |
| ML layer (RandomForest + IsolationForest) | done | retrain on real collected findings |
| Dashboard | done | screenshots for the report |
| Target CloudFormation stack | done | deploy it once |
| Continuous scheduling (Lambda + EventBridge) | written | deploy and let it fire once |
| SNS alerting | written | create the topic, confirm the email subscription |
| Evaluation results | not started | the before/after table below |
| Report and slides | not started | Day 3 |

## Three working days to 80%

### Day 1 — get it running against real AWS

1. Canvas → **Start Lab**, wait for the green dot, open **AWS Details**, copy all
   three credential values into your shell. They expire when the session ends.
2. Click **Readme** in the lab and screenshot the allowed service list. Confirm
   S3, EC2, IAM, RDS, CloudTrail, KMS and Lambda are there. If any collector is
   denied, it logs a warning and skips — that is by design, but note which ones
   so you can say so in the viva.
3. Deploy the target stack:
   ```
   aws cloudformation deploy --template-file infra/target_stack.yaml \
     --stack-name guardian-target --region us-east-1 \
     --parameter-overrides VpcId=<default-vpc-id>
   ```
   Get the VPC id with `aws ec2 describe-vpcs --query "Vpcs[0].VpcId" --output text`.
4. `python -m guardian.pipeline --region us-east-1 -v` and confirm it finds the
   planted misconfigurations. **Screenshot this terminal output.** It is your
   proof the collector talks to real AWS.
5. Run once with `--nvd` so the CTI cache holds live feed data rather than the
   fallback. It takes about a minute.

### Day 2 — the evaluation, which is what earns the marks

This is the part no generated code can do for you, and the part an examiner
will actually probe.

1. Record the baseline: posture score, finding count, severity mix.
2. Remediate in three waves, re-running the pipeline after each:
   - wave 1: fix the two Critical/High network findings (delete the open SG rules)
   - wave 2: enable encryption and versioning on the patient records bucket
   - wave 3: create a multi-region CloudTrail
3. You now have four points on the trend line and a table like this:

   | Run | Action taken | Posture | Open | Critical+High |
   |---|---|---|---|---|
   | 1 | baseline | | | |
   | 2 | closed security group | | | |
   | 3 | encryption + versioning | | | |
   | 4 | CloudTrail enabled | | | |

4. Also record: total assessment runtime, checks per second, and the model's
   accuracy and macro-F1 from `models/metrics.json`. Quantitative results turn a
   demo into a project.
5. Deploy `lambda_handler.py` on a 6-hour EventBridge schedule and let it fire
   once. Screenshot the CloudWatch log line and the S3 snapshot. That screenshot
   is your evidence for the word "continuous".

### Day 3 — write it up

- Regenerate the architecture diagram to match what you actually built. The
  current one shows MongoDB, Grafana and OpenCTI, none of which exist in the
  code; an examiner who notices that will assume nothing was built.
- Add a "Deviations from proposed stack" subsection. Copy the justifications
  from README.md. Owning a deliberate change reads as engineering judgement;
  leaving the mismatch unexplained reads as an unfinished project.
- Slides: problem (2), architecture as built (1), live demo (4 min), evaluation
  table (1), what is left (1).

## Suggested split across the three of you

- **Arun** — Day 1 AWS deployment and collector verification, GitHub hygiene
  (commit in small steps with real messages; a single "initial commit" dump the
  night before is visible and looks bad), report assembly.
- **Saharsh** — dashboard screenshots, architecture diagram redraw, the Day 2
  remediation waves and the before/after evaluation table.
- **Kamalnayak** — CTI verification with live feeds, model retraining on the real
  collected findings, `models/metrics.json` write-up, Lambda and SNS deployment.

## Demo script (four minutes, rehearse it once)

1. Dashboard open on the baseline run. Point at the posture score and the two
   PHI-tagged critical findings. *"This account would fail a HIPAA audit on
   164.312(a)(1)."*
2. Expand one finding. Show evidence, the framework mapping, the ATT&CK
   technique, and the fix.
3. Show the threat intelligence panel. *"This ranking is not static — the
   security group finding is up-weighted because remote-access vulnerabilities
   currently account for N entries in the CISA exploited catalogue."*
4. Terminal: fix the security group, re-run, reload. The trend line moves.
5. Close on the evaluation table and the CloudWatch log proving it runs unattended.

## Questions to prepare for

- *Why not just use AWS Security Hub?* Not available in the Learner Lab, and
  Security Hub does not weight findings by live exploitation data or by whether
  the resource holds PHI. Say both parts.
- *What does the AI actually add?* The IsolationForest surfaces findings that are
  unusual for this account; the RandomForest lets the ranking be retrained on a
  specific hospital's triage history instead of staying at our hard-coded weights.
  Be honest that the current model is trained on a bootstrapped set — and say what
  real training data you would collect. Overclaiming here is the fastest way to
  lose marks.
- *How is this continuous?* EventBridge every six hours, KEV refreshed every 12,
  SNS alert on score drop or new Critical.
