
class ImageComparator:
    def __init__(self):
        import torch
        from torchvision import models, transforms

        # Load pretrained model
        model = models.resnet50(weights='ResNet50_Weights.DEFAULT')
        model.eval()
        self.feature_extractor = torch.nn.Sequential(*list(model.children())[:-1])

        # Preprocessing
        self.preprocess = transforms.Compose([
            transforms.Resize(256),
            transforms.ToTensor(),
            transforms.Normalize(mean=[0.485, 0.456, 0.406],
                                 std=[0.229, 0.224, 0.225])
        ])

        # Keep references so you don’t re-import
        import torch.nn.functional as F
        self.F = F
        self.torch = torch

    def get_embedding(self, image):
        image = image.convert("RGB")
        img_tensor = self.preprocess(image).unsqueeze(0)
        with self.torch.no_grad():
            features = self.feature_extractor(img_tensor)
            return features.flatten(1)

    def get_similarity(self, image1, image2):
        emb1 = self.get_embedding(image1)
        emb2 = self.get_embedding(image2)
        return self.F.cosine_similarity(emb1, emb2)[0].item()
