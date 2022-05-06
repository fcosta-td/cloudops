#!/usr/bin/env bash

PRIV_KEY="sa-signer.key"
PUB_KEY="sa-signer.key.pub"
PKCS_KEY="sa-signer-pkcs8.pub"

# Generate a key pair
ssh-keygen -t rsa -b 2048 -f ./keys/$PRIV_KEY -m pem
# convert the SSH pubkey to PKCS8
ssh-keygen -e -m PKCS8 -f ./keys/$PUB_KEY > ./keys/$PKCS_KEY

export S3_BUCKET="oidc"
# Create the bucket if it doesn't exist
_bucket_name=$(awslocal s3api list-buckets  --query "Buckets[?Name=='$S3_BUCKET'].Name | [0]" --out text)
if [[ $_bucket_name == "None" ]]; then
    awslocal s3api create-bucket --bucket $S3_BUCKET
fi
echo "export S3_BUCKET=$S3_BUCKET"
export ISSUER_HOSTPATH="0.0.0.0:4566/$S3_BUCKET"

cat <<EOF > ./keys/discovery.json
{
    "issuer": "https://$ISSUER_HOSTPATH",
    "jwks_uri": "https://$ISSUER_HOSTPATH/keys.json",
    "authorization_endpoint": "urn:kubernetes:programmatic_authorization",
    "response_types_supported": [
        "id_token"
    ],
    "subject_types_supported": [
        "public"
    ],
    "id_token_signing_alg_values_supported": [
        "RS256"
    ],
    "claims_supported": [
        "sub",
        "iss"
    ]
}
EOF

mypath=$(pwd)
echo "$mypath"
cd amazon-eks-pod-identity-webhook-master/hack/self-hosted
go run main.go -key $mypath/keys/$PKCS_KEY | jq '.keys += [.keys[0]] | .keys[1].kid = ""' > $mypath/keys/keys.json

cd $mypath

awslocal s3 cp --acl public-read ./keys/discovery.json s3://$S3_BUCKET/.well-known/openid-configuration
awslocal s3 cp --acl public-read ./keys/keys.json s3://$S3_BUCKET/keys.json

## Kind cluster ###
cat <<EOF | kind create cluster --config=-
kind: Cluster
apiVersion: kind.x-k8s.io/v1alpha4
name: kind
nodes:
- role: control-plane
  extraMounts:
    - hostPath: $(pwd)/keys/sa-signer-pkcs8.pub
      containerPath: /etc/kubernetes/pki/sa.pub
    - hostPath: $(pwd)/keys/sa-signer.key
      containerPath: /etc/kubernetes/pki/sa.key
  kubeadmConfigPatches:
  - |
    kind: ClusterConfiguration
    apiServer:
      extraArgs:
        service-account-key-file: /etc/kubernetes/pki/sa.pub
        service-account-signing-key-file: /etc/kubernetes/pki/sa.key
        api-audiences: aud
        service-account-issuer: https://0.0.0.0:4566/oidc
    controllerManager:
      extraArgs:
        service-account-private-key-file: /etc/kubernetes/pki/sa.key
EOF

## certmanager and webhook
kubectl apply --validate=false -f https://github.com/jetstack/cert-manager/releases/download/v1.7.0/cert-manager.yaml
cmctl check api --namespace cert-manager --wait=2m
kubectl apply --validate=false -f ../certmanager/certmanager.yaml
kubectl apply -f ./amazon-eks-pod-identity-webhook-master/deploy/auth.yaml
kubectl apply -f ./amazon-eks-pod-identity-webhook-master/deploy/deployment-base.yaml
kubectl apply -f ./amazon-eks-pod-identity-webhook-master/deploy/mutatingwebhook.yaml
kubectl apply -f ./amazon-eks-pod-identity-webhook-master/deploy/service.yaml

SERVICE="iam"
AWS_ACCOUNT_ID=$(awslocal sts get-caller-identity --query "Account" --output text)
OIDC_PROVIDER=$ISSUER_HOSTPATH
ACK_K8S_NAMESPACE=ack-system
ACK_K8S_SERVICE_ACCOUNT_NAME=ack-$SERVICE-controller

read -r -d '' TRUST_RELATIONSHIP <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": {
        "Federated": "arn:aws:iam::${AWS_ACCOUNT_ID}:oidc-provider/${OIDC_PROVIDER}"
      },
      "Action": "sts:AssumeRoleWithWebIdentity",
      "Condition": {
        "StringEquals": {
          "${OIDC_PROVIDER}:sub": "system:serviceaccount:${ACK_K8S_NAMESPACE}:${ACK_K8S_SERVICE_ACCOUNT_NAME}"
        }
      }
    }
  ]
}
EOF
echo "${TRUST_RELATIONSHIP}" > trust.json

ACK_CONTROLLER_IAM_ROLE="ack-${SERVICE}-controller"
ACK_CONTROLLER_IAM_ROLE_DESCRIPTION='IRSA role for ACK $SERVICE controller deployment on EKS cluster using Helm charts'
awslocal iam create-role --role-name "${ACK_CONTROLLER_IAM_ROLE}" --assume-role-policy-document file://trust.json --description "${ACK_CONTROLLER_IAM_ROLE_DESCRIPTION}"
ACK_CONTROLLER_IAM_ROLE_ARN=$(awslocal iam get-role --role-name=$ACK_CONTROLLER_IAM_ROLE --query Role.Arn --output text)
awslocal iam create-policy --policy-name iam-controller --policy-document file://policy.json
awslocal iam attach-role-policy --role-name "${ACK_CONTROLLER_IAM_ROLE}" --policy-arn "arn:aws:iam::000000000000:policy/iam-controller"



helm upgrade --install iam-controller ../iam/chart \
  --create-namespace --namespace=ack-system \
  --values ../iam/chart/custom_values.yaml
