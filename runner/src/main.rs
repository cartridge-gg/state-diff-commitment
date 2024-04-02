use std::{path::Path, process::Stdio};

use anyhow::{bail, Context};
use serde_json::{to_string_pretty, Value};
use tokio::{
    fs::{self, File},
    io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader},
    process::Command,
};

async fn run(mut command: Command, input: Option<String>) -> anyhow::Result<String> {
    command
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .stdin(Stdio::piped());

    let mut child = command.spawn()?;

    if let Some(input) = input {
        let mut stdin = child.stdin.take().context("failed to open stdin")?;

        tokio::spawn(async move {
            stdin.write_all(input.as_bytes()).await.unwrap();
        });
    }

    let stdout = child.stdout.take().context("failed to open stdout")?;
    let reader = BufReader::new(stdout);
    let mut lines = reader.lines();
    let mut out = String::new();
    while let Some(line) = lines.next_line().await? {
        println!("{}", line);
        out.push_str(&line);
    }

    let status = child.wait().await?;

    if !status.success() {
        if let Some(mut output) = child.stderr.take() {
            let mut err = Vec::new();
            output.read_to_end(&mut err).await?;

            // Handle error output
            let err = String::from_utf8(err).context("failed to parse stderr")?;
            bail!("Podman error: {}", err)
        };
        bail!("Error without stderr")
    }

    Ok(out)
}

impl Prover {
    pub async fn pull(&self, prover: &str, verifier: &str) -> anyhow::Result<()> {
        // podman pull neotheprogramist/verifier:latest
        let mut command = Command::new("podman");
        command.arg("pull").arg(format!("docker.io/{}", prover));

        run(command, None).await.context("Failed to pull prover")?;

        let mut command = Command::new("podman");
        command.arg("pull").arg(format!("docker.io/{}", verifier));

        run(command, None)
            .await
            .context("Failed to pull verifier")?;

        Ok(())
    }

    pub async fn rebuild(&self) -> anyhow::Result<()> {
        let mut rebuild_prover = Command::new("podman");
        rebuild_prover
            .arg("build")
            .arg("-t")
            .arg(&self.0)
            .arg("-f")
            .arg("Dockerfile")
            .arg(".");

        run(rebuild_prover, None)
            .await
            .context("Failed to rebuild prover")?;

        Ok(())
    }

    pub async fn prove(&self) -> anyhow::Result<String> {
        let filename = Path::new("src").join("input.json");
        let file_content = fs::read_to_string(filename).await?;

        let mut command = Command::new("podman");
        command.arg("run").arg("-i").arg("--rm").arg(&self.0);

        run(command, Some(file_content)).await
    }

    pub async fn verify(proof: String) -> anyhow::Result<()> {
        let mut command = Command::new("podman");
        command.arg("run").arg("-i").arg("--rm").arg("verifier");

        run(command, Some(proof)).await?;

        Ok(())
    }
}

pub struct Prover(String);

#[tokio::main]
async fn main() {
    // prepare
    let prover = Prover("state-diff-commitment".to_string());
    prover
        .pull(
            "neotheprogramist/stone5-poseidon3:latest",
            "neotheprogramist/verifier:latest",
        )
        .await
        .unwrap();
    prover.rebuild().await.unwrap();

    // proof and verify
    let proof = prover.prove().await.unwrap();
    Prover::verify(proof.to_owned()).await.unwrap();

    let mut file = File::create("proof.json").await.unwrap();
    let json: Value = serde_json::from_str(&proof).unwrap();
    file.write_all(to_string_pretty(&json).unwrap().as_bytes()).await.unwrap();
}
